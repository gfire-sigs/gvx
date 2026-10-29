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

//go:build darwin && arm64

package hvf

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// TestAddressSpaceChurnReusesTablesWithoutLeakOrAliasing is the regression test
// for the stale walk-cache hazard. Every iteration builds a fresh address
// space, which reuses the table pages that the previous one released. The
// guest reads a value that only this iteration wrote. A stale cached walk would
// read the previous iteration's memory or fault. The slab must not grow.
func TestAddressSpaceChurnReusesTablesWithoutLeakOrAliasing(t *testing.T) {
	plat := newTestPlatform(t)
	vm := plat.vm
	ctx := plat.NewContext(context.Background()).(*Context)
	ac := arch.New(arch.Host)

	runOnce := func(i int) {
		asIface, err := plat.NewAddressSpace(platform.AddressSpaceOptions{})
		if err != nil {
			t.Fatalf("iteration %d: NewAddressSpace: %v", i, err)
		}
		as := asIface.(*AddressSpace)
		arena, err := memutil.AllocateAnonymousArena(hostPageSize)
		if err != nil {
			t.Fatalf("iteration %d: arena: %v", i, err)
		}
		binary.LittleEndian.PutUint32(arena[0:], 0xf9400001) // LDR X1, [X0]
		binary.LittleEndian.PutUint32(arena[4:], insnSVC0)
		const marker = 0x5eed_0000
		binary.LittleEndian.PutUint64(arena[pageSize4K:], marker+uint64(i))
		mapHostBytes(t, as, guestCodeAddr, arena[:pageSize4K], hostarch.AccessType{Read: true, Execute: true})
		// A distant data address uses different level-0, level-1 and level-2 tables.
		dataVA := hostarch.Addr(0x7f00_0000_0000) + hostarch.Addr(i%7)*0x4000_0000
		mapHostBytes(t, as, dataVA, arena[pageSize4K:2*pageSize4K], hostarch.ReadWrite)

		ac.SetIP(uintptr(guestCodeAddr))
		ac.SetStack(uintptr(dataVA) + 0x800)
		ac.StateData().Regs.Regs[0] = uint64(dataVA)
		ac.StateData().Regs.Regs[1] = 0
		mm := &stubMemoryManager{as: as}
		sig, _, err := ctx.Switch(context.Background(), mm, ac, 0)
		if sig != nil || err != nil {
			t.Fatalf("iteration %d: Switch = (%v, %v)", i, sig, err)
		}
		if got := ac.StateData().Regs.Regs[1]; got != marker+uint64(i) {
			t.Fatalf("iteration %d: the guest read %#x, want %#x", i, got, marker+uint64(i))
		}
		as.Release()
		if err := memutil.UnmapView(arena); err != nil {
			t.Fatalf("iteration %d: UnmapView: %v", i, err)
		}
	}

	runOnce(0) // Warm up the slab and the worker.
	before, blocksBefore := vm.slabStats(), vm.regions.regionCount()
	for i := 1; i <= 400; i++ {
		runOnce(i)
	}
	after, blocksAfter := vm.slabStats(), vm.regions.regionCount()
	if after != before {
		t.Errorf("slab after 400 address spaces = %+v, want %+v: table pages leak", after, before)
	}
	if blocksAfter != blocksBefore {
		t.Errorf("regions after churn = %d, want %d: Stage-2 mappings leak", blocksAfter, blocksBefore)
	}
}

func TestUnmapStopsRunningVCPUsBeforeReturning(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnLdrX1X0, 0x17ffffff) // LDR X1,[X0]; B .-4
	g.regs().Regs[0] = uint64(guestDataAddr)
	for i := range 100 {
		res := g.switchAsync()
		waitInGuest(t, g.ctx)
		g.as.Unmap(guestDataAddr, pageSize4K)
		got := receive(t, res)
		if !errors.Is(got.err, platform.ErrContextSignal) || got.sig == nil || got.sig.Signo != int32(linux.SIGSEGV) {
			t.Fatalf("iteration %d: Switch = (%v, %v), want SIGSEGV after the unmap", i, got.sig, got.err)
		}
		if got.sig.Code != sigSegvMap || got.sig.Addr() != uint64(guestDataAddr) {
			t.Fatalf("iteration %d: signal code %d addr %#x, want SEGV_MAPERR at the data page", i, got.sig.Code, got.sig.Addr())
		}
		g.ac.SetIP(uintptr(guestCodeAddr))
		mapHostBytes(t, g.as, guestDataAddr, g.data, hostarch.ReadWrite)
	}
}

func TestReleaseOfRunningAddressSpaceStopsTheGuest(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnBSelf)
	res := g.switchAsync()
	waitInGuest(t, g.ctx)
	g.as.Release()
	got := receive(t, res)
	if !errors.Is(got.err, errPageTableReleased) {
		t.Fatalf("Switch after Release = (%v, %v), want errPageTableReleased", got.sig, got.err)
	}
	if _, _, err := g.switchOnce(); !errors.Is(err, errPageTableReleased) {
		t.Fatalf("second Switch = %v, want errPageTableReleased", err)
	}
}

func TestRegionsAreSharedAndOutliveUnmap(t *testing.T) {
	plat := newTestPlatform(t)
	regions := plat.vm.regions
	base := regions.regionCount()
	a := newGuest(t, plat, insnLdrX1X0, insnSVC0)
	if got := regions.regionCount(); got != base+1 {
		t.Fatalf("one arena maps %d regions, want 1", got-base)
	}
	// A second address space maps the same file: the region is shared.
	asIface, err := plat.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b := asIface.(*AddressSpace)
	if err := b.MapFile(guestCodeAddr, a.file, memmap.FileRange{Start: 0, End: pageSize4K}, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	if got := regions.regionCount(); got != base+1 {
		t.Fatalf("a second mapping of the same file maps %d regions, want 1", got-base)
	}
	a.as.Unmap(guestCodeAddr, 2*pageSize4K)
	if got := regions.regionCount(); got != base+1 {
		t.Fatalf("Unmap changed the region count to %d", got-base)
	}
	b.Release()
	if got := regions.regionCount(); got != base+1 {
		t.Fatalf("the region went away while the first address space uses it (%d)", got-base)
	}
	a.as.Release()
	if got := regions.regionCount(); got != base {
		t.Fatalf("%d regions stay mapped after the last user left", got-base)
	}
}

func TestMapReplacementSwitchesTheGuestToTheNewMemory(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnLdrX1X0, insnSVC0)
	other, err := memutil.AllocateAnonymousArena(hostPageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer memutil.UnmapView(other)
	binary.LittleEndian.PutUint64(g.data[8:], 0x1122)
	binary.LittleEndian.PutUint64(other[8:], 0x3344)
	for round := range 3 {
		if got, sig, err := g.read64(guestDataAddr + 8); sig != nil || err != nil || got != 0x1122 {
			t.Fatalf("round %d: the guest read (%#x, %v, %v) from the original page, want 0x1122", round, got, sig, err)
		}
		mapHostBytes(t, g.as, guestDataAddr, other[:pageSize4K], hostarch.ReadWrite)
		if got, sig, err := g.read64(guestDataAddr + 8); sig != nil || err != nil || got != 0x3344 {
			t.Fatalf("round %d: the guest read (%#x, %v, %v) after the replacement, want 0x3344", round, got, sig, err)
		}
		mapHostBytes(t, g.as, guestDataAddr, g.data, hostarch.ReadWrite)
	}
}

// A vCPU can keep a cached translation of the old page while the Sentry
// replaces a mapping. MapFile must stop that vCPU before it returns, because
// the Sentry then reuses the old memory. The guest copies a word from the
// mapped page into an observer page in a loop. The test poisons the old page
// after each replacement and checks that the observer never shows the poison.
func TestReplacementStopsVCPUsBeforeTheOldMemoryChanges(t *testing.T) {
	plat := newTestPlatform(t)
	const observerVA = hostarch.Addr(0x500000)
	// LDR X1,[X0]; STR X1,[X2]; B .-8.
	g := newGuest(t, plat, insnLdrX1X0, insnStrX1X2, 0x17fffffe)
	observer, err := memutil.AllocateAnonymousArena(hostPageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer memutil.UnmapView(observer)
	mapHostBytes(t, g.as, observerVA, observer[:pageSize4K], hostarch.ReadWrite)
	pages := [2][]byte{g.data, make([]byte, 0)}
	other, err := memutil.AllocateAnonymousArena(hostPageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer memutil.UnmapView(other)
	pages[1] = other[:pageSize4K]
	binary.LittleEndian.PutUint64(pages[0], 1)
	binary.LittleEndian.PutUint64(pages[1], 2)
	g.regs().Regs[0] = uint64(guestDataAddr)
	g.regs().Regs[2] = uint64(observerVA)

	res := g.switchAsync()
	waitInGuest(t, g.ctx)
	const poison = 0xdead
	cur := 0
	for i := range 60 {
		next := 1 - cur
		mapHostBytes(t, g.as, guestDataAddr, pages[next], hostarch.ReadWrite)
		binary.LittleEndian.PutUint64(pages[cur], poison)
		// The guest resumes after MapFile returns. It can store its saved
		// register once, which holds the old valid value. It must never read
		// the poisoned old page. Poll for the new value, and stop at once on
		// the poison.
		observed := func() uint64 { return atomic.LoadUint64((*uint64)(unsafe.Pointer(&observer[0]))) }
		deadline := time.Now().Add(2 * time.Second)
		for got := observed(); got != uint64(next+1); got = observed() {
			if got == poison {
				t.Fatalf("iteration %d: the observer holds the poison %#x: a vCPU read the old page after MapFile returned", i, got)
			}
			if time.Now().After(deadline) {
				t.Fatalf("iteration %d: the observer holds %#x after 2s, want %d: the guest did not read the new page", i, got, next+1)
			}
			runtime.Gosched()
		}
		// A vCPU with a stale translation would read the old page again.
		for range 256 {
			if got := observed(); got == poison {
				t.Fatalf("iteration %d: the observer holds the poison %#x after the new value: a vCPU read the old page after MapFile returned", i, got)
			}
			runtime.Gosched()
		}
		binary.LittleEndian.PutUint64(pages[cur], uint64(cur+1))
		cur = next
	}
	g.ctx.Interrupt()
	if got := receive(t, res); !errors.Is(got.err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch = (%v, %v), want ErrContextInterrupt", got.sig, got.err)
	}
}

// testFile is a memmap.File whose MapInternal returns a fixed host slice.
type testFile struct {
	memmap.File
	mem []byte
}

func (f *testFile) MapInternal(fr memmap.FileRange, _ hostarch.AccessType) (safemem.BlockSeq, error) {
	return safemem.BlockSeqOf(safemem.BlockFromSafeSlice(f.mem[fr.Start:fr.End])), nil
}

func TestReadOnlyFileDescriptorMappingUsesACopy(t *testing.T) {
	plat := newTestPlatform(t)
	regions := plat.vm.regions

	f, err := os.CreateTemp(t.TempDir(), "image")
	if err != nil {
		t.Fatal(err)
	}
	content := make([]byte, hostPageSize)
	binary.LittleEndian.PutUint64(content[0:], 0xfeedc0de)
	if _, err := f.WriteAt(content, 0); err != nil {
		t.Fatal(err)
	}
	f.Close()
	ro, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	mem, err := unix.Mmap(int(ro.Fd()), 0, hostPageSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mem)

	g := newGuest(t, plat, insnLdrX1X0, insnSVC0)
	baseRegions, baseCopies := regions.regionCount(), regions.copyCount()
	file := &testFile{mem: mem}
	fr := memmap.FileRange{Start: 0, End: pageSize4K}
	if err := g.as.MapFile(guestDataAddr+0x10000, file, fr, hostarch.Read, false); err != nil {
		t.Fatalf("read-only MapFile: %v", err)
	}
	if got := regions.copyCount(); got != baseCopies+1 {
		t.Errorf("private copies = %d, want %d: the read-only descriptor mapping did not use a copy", got, baseCopies+1)
	}
	if got, sig, err := g.read64(guestDataAddr + 0x10000); sig != nil || err != nil || got != 0xfeedc0de {
		t.Errorf("the guest read (%#x, %v, %v), want the file content 0xfeedc0de", got, sig, err)
	}

	// A writable mapping of the same memory must fail: a copy would diverge.
	err = g.as.MapFile(guestDataAddr+0x20000, file, fr, hostarch.ReadWrite, false)
	if !errors.Is(err, errHostBlockRejected) {
		t.Errorf("writable MapFile of read-only memory = %v, want errHostBlockRejected", err)
	}
	// Unmap changes only Stage-1: the copy stays for the next mapping.
	g.as.Unmap(guestDataAddr+0x10000, pageSize4K)
	if got := regions.copyCount(); got != baseCopies+1 {
		t.Errorf("private copies = %d after the unmap, want %d: Unmap changed Stage-2", got, baseCopies+1)
	}
	if _, sig, err := g.read64(guestDataAddr + 0x10000); sig == nil && err == nil {
		t.Error("the guest read an unmapped page")
	}
	g.as.Release()
	if got := regions.copyCount(); got != baseCopies {
		t.Errorf("private copies = %d after Release, want %d: the copy leaked", got, baseCopies)
	}
	if got := regions.regionCount(); got != baseRegions-1 {
		t.Errorf("regions = %d after Release, want %d: the last user left", got, baseRegions-1)
	}
}

// The Sentry maps whole hostarch pages of 4KB. The Stage-1 granule is 4KB too,
// so one MapFile call must install every page of the range.
func TestMapFileCoversWholeHostarchPages(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnLdrX1X0, insnSVC0)
	const pages = 4
	size := uint64(pages * hostarch.PageSize)
	mem, err := memutil.AllocateAnonymousArena(int(size))
	if err != nil {
		t.Fatal(err)
	}
	defer memutil.UnmapView(mem)
	for i := 0; i < len(mem); i += pageSize4K {
		binary.LittleEndian.PutUint64(mem[i:], uint64(i/pageSize4K+1))
		binary.LittleEndian.PutUint64(mem[i+pageSize4K-8:], uint64(0xf0+i/pageSize4K%16))
	}
	base := hostarch.Addr(0x1000000)
	if err := g.as.MapFile(base, &testFile{mem: mem}, memmap.FileRange{Start: 0, End: size}, hostarch.ReadWrite, false); err != nil {
		t.Fatalf("MapFile of %d bytes: %v", size, err)
	}
	for i := 0; i < len(mem); i += pageSize4K {
		first, second := binary.LittleEndian.Uint64(mem[i:]), binary.LittleEndian.Uint64(mem[i+pageSize4K-8:])
		for _, c := range []struct {
			off  hostarch.Addr
			want uint64
		}{{hostarch.Addr(i), first}, {hostarch.Addr(i + pageSize4K - 8), second}} {
			if got, sig, err := g.read64(base + c.off); sig != nil || err != nil || got != c.want {
				t.Fatalf("guest read at +%#x = (%#x, %v, %v), want %#x", uint64(c.off), got, sig, err, c.want)
			}
		}
	}
}

func TestMapFileRejectsUnalignedRanges(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat)
	file := &testFile{mem: g.arena}
	var segv platform.SegmentationFault
	for _, tc := range []struct {
		name string
		addr hostarch.Addr
		fr   memmap.FileRange
	}{
		{"unaligned address", guestDataAddr + 8, memmap.FileRange{Start: 0, End: pageSize4K}},
		{"unaligned start", guestDataAddr + 0x10000, memmap.FileRange{Start: 8, End: pageSize4K}},
		{"unaligned end", guestDataAddr + 0x10000, memmap.FileRange{Start: 0, End: 100}},
		{"empty range", guestDataAddr + 0x10000, memmap.FileRange{Start: 0, End: 0}},
	} {
		if err := g.as.MapFile(tc.addr, file, tc.fr, hostarch.Read, false); !errors.As(err, &segv) {
			t.Errorf("%s: MapFile = %v, want SegmentationFault", tc.name, err)
		}
	}
}

func TestMoreContextsThanVCPUsAllMakeProgress(t *testing.T) {
	plat := newTestPlatform(t)
	limitWorkers(t, plat, 3)
	const contexts, rounds = 10, 3
	guests := make([]*guest, contexts)
	for i := range guests {
		guests[i] = newGuest(t, plat, insnBSelf)
	}
	var wg sync.WaitGroup
	var finished atomic.Int32
	errs := make(chan error, contexts)
	for _, g := range guests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer finished.Add(1)
			for range rounds {
				if _, _, err := g.switchOnce(); !errors.Is(err, platform.ErrContextInterrupt) {
					errs <- err
					return
				}
			}
		}()
	}
	// The kernel preempts running tasks when more run than vCPUs exist.
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		for finished.Load() < contexts {
			for _, g := range guests {
				g.ctx.Preempt()
			}
			runtime.Gosched()
		}
	}()
	wg.Wait()
	<-stop
	close(errs)
	for err := range errs {
		t.Errorf("a Switch returned %v, want ErrContextInterrupt", err)
	}
	if got := plat.ConcurrencyCount(); got != 3 {
		t.Errorf("ConcurrencyCount() = %d, want the vCPU limit 3", got)
	}
}

func TestInterruptEndsAWaitForAVCPU(t *testing.T) {
	plat := newTestPlatform(t)
	limitWorkers(t, plat, 1)
	hog := newGuest(t, plat, insnBSelf)
	waiter := newGuest(t, plat, insnSVC0)
	hogRes := hog.switchAsync()
	waitInGuest(t, hog.ctx)

	waitRes := waiter.switchAsync()
	// The waiter blocks: the only vCPU runs the hog. Wait until it queued.
	for {
		plat.vm.pool.mu.Lock()
		queued := len(plat.vm.pool.waiters)
		plat.vm.pool.mu.Unlock()
		if queued == 1 {
			break
		}
		runtime.Gosched()
	}
	waiter.ctx.Interrupt()
	got := receive(t, waitRes)
	if !errors.Is(got.err, platform.ErrContextInterrupt) {
		t.Fatalf("waiting Switch = (%v, %v), want ErrContextInterrupt", got.sig, got.err)
	}
	hog.ctx.Interrupt()
	if got := receive(t, hogRes); !errors.Is(got.err, platform.ErrContextInterrupt) {
		t.Fatalf("hog Switch = (%v, %v)", got.sig, got.err)
	}
}

func TestCloseDestroysVCPUsAndTheVM(t *testing.T) {
	requireHypervisor(t)
	for i := range 8 {
		p, err := New()
		if err != nil {
			t.Fatalf("iteration %d: New: %v", i, err)
		}
		g := newGuest(t, p, insnSVC0)
		if sig, _, err := g.switchOnce(); sig != nil || err != nil {
			t.Fatalf("iteration %d: Switch = (%v, %v)", i, sig, err)
		}
		g.as.Release()
		if err := p.Close(); err != nil {
			t.Fatalf("iteration %d: Close: %v", i, err)
		}
		if err := p.Close(); err != nil {
			t.Fatalf("iteration %d: second Close: %v", i, err)
		}
		// hv_vm_create fails with HV_BUSY while the old VM or any vCPU exists.
		if err := hvVMCreate(); err != nil {
			t.Fatalf("iteration %d: the VM survived Close: %v", i, err)
		}
		if err := hvVMDestroy(); err != nil {
			t.Fatalf("iteration %d: hv_vm_destroy: %v", i, err)
		}
	}
}

func TestPlatformsShareOneVMUntilTheLastCloses(t *testing.T) {
	requireHypervisor(t)
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if a.vm != b.vm {
		t.Fatal("two Platforms hold different VMs")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	g := newGuest(t, b, insnSVC0)
	if sig, _, err := g.switchOnce(); sig != nil || err != nil {
		t.Fatalf("Switch on the surviving Platform = (%v, %v)", sig, err)
	}
	g.as.Release()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUseAfterCloseFailsExplicitly(t *testing.T) {
	requireHypervisor(t)
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	g := newGuest(t, p, insnSVC0)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.switchOnce(); !errors.Is(err, errPlatformClosed) {
		t.Errorf("Switch after Close = %v, want errPlatformClosed", err)
	}
	if _, err := p.NewAddressSpace(platform.AddressSpaceOptions{}); !errors.Is(err, errPlatformClosed) {
		t.Errorf("NewAddressSpace after Close = %v, want errPlatformClosed", err)
	}
	mem, err := memutil.AllocateAnonymousArena(hostPageSize)
	if err != nil {
		t.Fatal(err)
	}
	defer memutil.UnmapView(mem)
	err = g.as.MapFile(0x800000, &testFile{mem: mem}, memmap.FileRange{Start: 0, End: pageSize4K}, hostarch.Read, false)
	if !errors.Is(err, errPlatformClosed) {
		t.Errorf("mapping after Close = %v, want errPlatformClosed", err)
	}
	// Releasing an address space after Close must not touch freed memory.
	g.as.Release()
}

func TestCloseStopsAGuestThatIsRunning(t *testing.T) {
	requireHypervisor(t)
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	g := newGuest(t, p, insnBSelf)
	res := g.switchAsync()
	waitInGuest(t, g.ctx)
	if err := p.Close(); err != nil {
		t.Fatalf("Close with a running guest: %v", err)
	}
	if got := receive(t, res); !errors.Is(got.err, errPlatformClosed) {
		t.Fatalf("Switch = (%v, %v), want errPlatformClosed", got.sig, got.err)
	}
}

func TestCloseRacingWithSwitchNeverHangs(t *testing.T) {
	requireHypervisor(t)
	for i := range 60 {
		p, err := New()
		if err != nil {
			t.Fatalf("iteration %d: New: %v", i, err)
		}
		const guests = 6
		var results [guests]<-chan switchResult
		for j := range guests {
			g := newGuest(t, p, insnSVC0, 0x17ffffff) // SVC #0; B .-4
			ch := make(chan switchResult, 1)
			results[j] = ch
			go func() {
				// Run system calls until the Platform stops the Context.
				for {
					sig, at, err := g.switchOnce()
					if err != nil || sig != nil {
						ch <- switchResult{sig, at, err}
						return
					}
					g.ac.SetIP(uintptr(guestCodeAddr))
				}
			}()
		}
		if err := p.Close(); err != nil {
			t.Fatalf("iteration %d: Close: %v", i, err)
		}
		for j, ch := range results {
			got := receive(t, ch)
			if !errors.Is(got.err, errPlatformClosed) {
				t.Fatalf("iteration %d guest %d: Switch ended with (%v, %v), want errPlatformClosed", i, j, got.sig, got.err)
			}
		}
	}
}

func TestPlatformRegistrationAndLimits(t *testing.T) {
	requireHypervisor(t)
	ctor, err := platform.Lookup(PlatformName)
	if err != nil {
		t.Fatalf("platform.Lookup(%q): %v", PlatformName, err)
	}
	p, err := ctor.New(platform.Options{})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	plat := p.(*Platform)
	defer plat.Close()
	if got := plat.MapUnit(); got != 2<<20 || got%hostarch.PageSize != 0 || got&(got-1) != 0 {
		t.Errorf("MapUnit() = %d, want 2 MiB, a power-of-two multiple of hostarch.PageSize %d", got, hostarch.PageSize)
	}
	if !FrameworkSymbolsLoaded() {
		t.Error("FrameworkSymbolsLoaded() = false")
	}
	if n := plat.ConcurrencyCount(); n < 1 || n > kernelCommPages {
		t.Errorf("ConcurrencyCount() = %d, want 1..%d", n, kernelCommPages)
	}
	if got := plat.MaxUserAddress(); got != 1<<48 {
		t.Errorf("MaxUserAddress() = %#x", uint64(got))
	}
}
