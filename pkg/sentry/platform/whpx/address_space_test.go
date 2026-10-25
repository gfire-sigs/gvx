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

package whpx

import (
	"errors"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// translate returns the guest physical address that the page tables of as
// map for va, and the permissions of the entry. Lookup reports the address of
// the page that it was asked for and the physical address of the start of the
// entry. A large entry starts at the address of va rounded down to its size.
func translate(as *AddressSpace, va uint64) (gpa uint64, opts hostarch.AccessType, user, ok bool) {
	_, phys, size, o := as.pt.Lookup(hostarch.Addr(va), false)
	if size == 0 {
		return 0, hostarch.AccessType{}, false, false
	}
	entryStart := va &^ (uint64(size) - 1)
	return uint64(phys) + (va &^ pageMask) - entryStart, o.AccessType, o.User, true
}

// hostOf returns the host address that the partition backs guest physical
// address gpa with.
func hostOf(fb *fakeBackend, gpa uint64) (unsafe.Pointer, bool) {
	_, host, ok := fb.mappingOf(gpa)
	return host, ok
}

func TestMapHostBuildsExactPageTableEntries(t *testing.T) {
	requireGuestPageSize(t)
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 3)

	if err := as.mapHost(0x400000, mem[:pageSize], hostarch.AccessType{Read: true, Execute: true}); err != nil {
		t.Fatal(err)
	}
	if err := as.mapHost(0x401000, mem[pageSize:2*pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if err := as.mapHost(0x402000, mem[2*pageSize:], hostarch.Read); err != nil {
		t.Fatal(err)
	}
	for i, c := range []struct {
		va   uint64
		want hostarch.AccessType
	}{
		{0x400000, hostarch.AccessType{Read: true, Execute: true}},
		{0x401000, hostarch.ReadWrite},
		{0x402000, hostarch.Read},
	} {
		gpa, got, user, ok := translate(as, c.va)
		if !ok || !user {
			t.Fatalf("page %#x is missing or supervisor-only", c.va)
		}
		if got.Write != c.want.Write || got.Execute != c.want.Execute {
			t.Errorf("page %#x has permissions %+v, want %+v", c.va, got, c.want)
		}
		host, mapped := hostOf(fb, gpa)
		if !mapped {
			t.Errorf("guest page %#x of %#x is not mapped in the partition", gpa, c.va)
		} else if host != unsafe.Pointer(&mem[i*pageSize]) {
			t.Errorf("guest page %#x of %#x maps host %p, want %p", gpa, c.va, host, &mem[i*pageSize])
		}
	}
	if _, _, _, ok := translate(as, 0x403000); ok {
		t.Error("a neighbouring page is mapped")
	}
	// The guest physical address is independent of the virtual address.
	gpa, _, _, _ := translate(as, 0x401000)
	if gpa == 0x401000 {
		t.Error("guest physical address equals the virtual address")
	}
}

func TestTwoAddressSpacesNeverAlias(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	a, b := newTestAS(t, p), newTestAS(t, p)
	if a.rootValue() == b.rootValue() {
		t.Fatal("address spaces share a page-table root")
	}
	memA := mustHost(t, fb, 1)
	memB := mustHost(t, fb, 1)
	// Both map different memory at the same virtual address.
	if err := a.mapHost(0x400000, memA, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if err := b.mapHost(0x400000, memB, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	ga, _, _, _ := translate(a, 0x400000)
	gb, _, _, _ := translate(b, 0x400000)
	if ga == gb {
		t.Fatalf("both address spaces map guest page %#x at 0x400000", ga)
	}
	if h, _ := hostOf(fb, ga); h != unsafe.Pointer(&memA[0]) {
		t.Error("a guest page maps the wrong host memory")
	}
	if h, _ := hostOf(fb, gb); h != unsafe.Pointer(&memB[0]) {
		t.Error("a guest page maps the wrong host memory")
	}
}

func TestAddressSpacesShareOneRegistrationOfAHostRange(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	a, b := newTestAS(t, p), newTestAS(t, p)
	mem := mustHost(t, fb, 4)

	maps0, _ := fb.calls()
	if err := a.mapHost(0x400000, mem, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if err := b.mapHost(0x800000, mem, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if err := b.mapHost(0xA00000, mem[pageSize:3*pageSize], hostarch.Read); err != nil {
		t.Fatal(err)
	}
	maps, unmaps := fb.calls()
	if maps-maps0 != 1 || unmaps != 0 {
		t.Errorf("three mappings of one host range made %d map calls and %d unmap calls, want 1 and 0", maps-maps0, unmaps)
	}
	ga, _, _, _ := translate(a, 0x400000)
	gb, _, _, _ := translate(b, 0x800000)
	if ga != gb {
		t.Errorf("a shared host page maps to %#x and %#x", ga, gb)
	}
	if gs, _, _, _ := translate(b, 0xA00000); gs != ga+pageSize {
		t.Errorf("a read-only view of the second page maps to %#x, want %#x", gs, ga+pageSize)
	}
	// Unmapping in one address space keeps the page for the other.
	b.Unmap(0x800000, 4*pageSize)
	if gpa, _, _, ok := translate(a, 0x400000); !ok || gpa != ga {
		t.Error("an Unmap in one address space changed the other")
	}
}

func TestMapFileUsesTheRequestedAccessAndRejectsBadHostMemory(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 5)
	fr := memmap.FileRange{Start: 0, End: 2 * pageSize}

	f := &fakeFile{blocks: []safemem.Block{safemem.BlockFromSafeSlice(mem[:2*pageSize])}}
	if err := as.MapFile(0x400000, f, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	if !f.lastAT.Read || !f.lastAT.Write {
		t.Errorf("MapInternal got %+v, want a writable request", f.lastAT)
	}
	for _, va := range []uint64{0x400000, 0x401000} {
		if _, got, _, ok := translate(as, va); !ok || !got.Write {
			t.Errorf("page %#x is not writable", va)
		}
	}

	// A read-only request asks MapInternal for a view without write access.
	r := &fakeFile{blocks: []safemem.Block{safemem.BlockFromSafeSlice(mem[2*pageSize : 4*pageSize])}}
	if err := as.MapFile(0x440000, r, fr, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	if !r.lastAT.Read || r.lastAT.Write {
		t.Errorf("MapInternal got %+v, want a read-only request", r.lastAT)
	}

	// A MapInternal failure is an error. There is no silent read-only retry.
	boom := errors.New("host mapping failed")
	g := &fakeFile{err: boom}
	if err := as.MapFile(0x500000, g, fr, hostarch.ReadWrite, false); !errors.Is(err, boom) {
		t.Errorf("MapFile returned %v", err)
	}
	if g.mapCalled != 1 {
		t.Errorf("MapInternal ran %d times", g.mapCalled)
	}
	if _, _, _, ok := translate(as, 0x500000); ok {
		t.Error("a failed MapFile left a mapping")
	}

	// A host slice that is not page aligned fails the whole call. The first
	// block must not reach the page tables.
	bad := &fakeFile{blocks: []safemem.Block{
		safemem.BlockFromSafeSlice(mem[4*pageSize : 5*pageSize]),
		safemem.BlockFromSafeSlice(mem[5*pageSize+8 : 6*pageSize+8]),
	}}
	if err := as.MapFile(0x600000, bad, fr, hostarch.Read, false); err == nil {
		t.Fatal("MapFile accepted unaligned host memory")
	}
	if _, _, _, ok := translate(as, 0x600000); ok {
		t.Error("the aligned block of a failed MapFile stays mapped")
	}

	// A file that returns more or fewer bytes than the range fails.
	short := &fakeFile{blocks: []safemem.Block{safemem.BlockFromSafeSlice(mem[:pageSize])}}
	if err := as.MapFile(0x700000, short, fr, hostarch.Read, false); err == nil {
		t.Error("MapFile accepted a host block shorter than the range")
	}

	for _, c := range []struct {
		name string
		addr hostarch.Addr
		fr   memmap.FileRange
		at   hostarch.AccessType
	}{
		{"unaligned address", 0x400800, fr, hostarch.Read},
		{"unaligned file range", 0x700000, memmap.FileRange{Start: 8, End: pageSize + 8}, hostarch.Read},
		{"empty range", 0x700000, memmap.FileRange{}, hostarch.Read},
		{"no access", 0x700000, fr, hostarch.NoAccess},
		{"above the user range", hostarch.Addr(p.maxUser()), fr, hostarch.Read},
		{"wrapping range", hostarch.Addr(^uint64(0) &^ pageMask), fr, hostarch.Read},
	} {
		if err := as.MapFile(c.addr, f, c.fr, c.at, false); err == nil {
			t.Errorf("MapFile accepted %s", c.name)
		}
	}
}

func TestMapFileFailureKeepsExistingMappings(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 2)
	if err := as.mapHost(0x400000, mem[:pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	gpa, _, _, _ := translate(as, 0x400000)
	boom := errors.New("partition refused")
	fb.mapErr = func(uint64) error { return boom }
	if err := as.mapHost(0x400000, mem[pageSize:], hostarch.ReadWrite); !errors.Is(err, boom) {
		t.Fatalf("mapHost returned %v", err)
	}
	if got, _, _, ok := translate(as, 0x400000); !ok || got != gpa {
		t.Error("a failed remap changed the existing mapping")
	}
}

// activeVP simulates a processor that runs guest code for as. It returns the
// processor and a function that makes it leave the guest.
func activeVP(t *testing.T, p *Platform, fb *fakeBackend, as *AddressSpace) (*vcpu, func()) {
	t.Helper()
	v, err := p.acquire(newContext(p))
	if err != nil {
		t.Fatal(err)
	}
	as.addActive(v)
	v.enter()
	return v, func() {
		v.leave()
		as.removeActive(v)
		p.release(v)
	}
}

// waitCancels blocks until the fake received n cancels for the processor.
func waitCancels(fb *fakeBackend, v *vcpu, n int) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	for fb.vps[v.index].cancels < n {
		fb.cond.Wait()
	}
}

// stopsBeforeReturn runs change while a processor runs guest code for as. It
// checks that change does not return before the processor left the guest, that
// the entry of va is gone or replaced by then, and that the generation
// advanced. A change that returns early would let the Sentry reuse a page
// that the processor can still reach.
func stopsBeforeReturn(t *testing.T, p *Platform, fb *fakeBackend, as *AddressSpace, va uint64, oldGPA uint64, change func()) {
	t.Helper()
	v, leave := activeVP(t, p, fb, as)
	genBefore := as.gen.Load()
	done := make(chan struct{})
	go func() {
		change()
		close(done)
	}()
	waitCancels(fb, v, 1)
	select {
	case <-done:
		t.Fatal("the change returned while the processor still ran guest code")
	default:
	}
	// The kick follows the page-table change, and the change still holds
	// as.mu while it waits, so the test reads the tables without the lock.
	gpa, _, _, ok := translate(as, va)
	if ok && gpa == oldGPA {
		t.Error("the old entry still names the page while the processor is being stopped")
	}
	if as.gen.Load() == genBefore {
		t.Error("the change did not advance the TLB generation")
	}
	leave()
	<-done
}

func TestUnmapStopsRunningProcessorsAndKeepsThePartitionMapped(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 1)
	if err := as.mapHost(0x400000, mem, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	gpa, _, _, _ := translate(as, 0x400000)
	maps0, unmaps0 := fb.calls()

	stopsBeforeReturn(t, p, fb, as, 0x400000, gpa, func() { as.Unmap(0x400000, pageSize) })

	if _, _, _, ok := translate(as, 0x400000); ok {
		t.Error("the page stays mapped in the page tables after Unmap")
	}
	if maps, unmaps := fb.calls(); maps != maps0 || unmaps != unmaps0 {
		t.Errorf("Unmap made %d map calls and %d unmap calls, want none", maps-maps0, unmaps-unmaps0)
	}
	if _, ok := hostOf(fb, gpa); !ok {
		t.Error("the registration of the host memory is gone after Unmap")
	}
}

func TestFreedPageTablesWaitForTheInvalidation(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 1)
	if err := as.mapHost(0x40000000, mem, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	v, leave := activeVP(t, p, fb, as)
	done := make(chan struct{})
	go func() {
		// The range covers a whole page table, so the page tables free it.
		as.Unmap(0x40000000, 2<<20)
		close(done)
	}()
	waitCancels(fb, v, 1)
	// The freed table waits in quarantine while the processor may still walk it.
	if q := as.alloc.Quarantined(); q == 0 {
		t.Error("no page table is quarantined after the last entry went away")
	}
	leave()
	<-done
	if q := as.alloc.Quarantined(); q != 0 {
		t.Errorf("%d page tables stay in quarantine after the invalidation", q)
	}
}

func TestReplacingAMappingStopsProcessorsBeforeItReturns(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 2)
	if err := as.mapHost(0x400000, mem[:pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	oldGPA, _, _, _ := translate(as, 0x400000)
	gen := as.gen.Load()
	// Mapping a new address does not invalidate anything.
	if err := as.mapHost(0x500000, mem[pageSize:], hostarch.Read); err != nil {
		t.Fatal(err)
	}
	if as.gen.Load() != gen {
		t.Error("a fresh mapping advanced the generation")
	}
	maps0, unmaps0 := fb.calls()
	stopsBeforeReturn(t, p, fb, as, 0x400000, oldGPA, func() {
		if err := as.mapHost(0x400000, mem[pageSize:], hostarch.Read); err != nil {
			t.Error(err)
		}
	})
	newGPA, got, _, ok := translate(as, 0x400000)
	if !ok || newGPA == oldGPA || got.Write {
		t.Errorf("the replaced entry maps %#x with %+v, want another read-only page", newGPA, got)
	}
	if _, unmaps := fb.calls(); unmaps != unmaps0 {
		t.Error("replacing a mapping unmapped guest memory in the partition")
	}
	if maps, _ := fb.calls(); maps != maps0 {
		t.Errorf("remapping registered host memory again: %d map calls", maps-maps0)
	}
}

func TestExecuteMappingsAdvanceTheCodeGeneration(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 2)
	before := as.execGen.Load()
	if err := as.mapHost(0x400000, mem[:pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if as.execGen.Load() != before {
		t.Error("a data mapping advanced the code generation")
	}
	if err := as.mapHost(0x401000, mem[pageSize:], hostarch.AccessType{Read: true, Execute: true}); err != nil {
		t.Fatal(err)
	}
	if as.execGen.Load() == before {
		t.Error("an executable mapping did not advance the code generation")
	}
}

func TestReleaseLeavesNoReachableMapping(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as, err := p.NewAddressSpace(platformASOptions)
	if err != nil {
		t.Fatal(err)
	}
	a := as.(*AddressSpace)
	mem := mustHost(t, fb, 4)
	var gpas [4]uint64
	for i := range 4 {
		va := 0x400000 + uint64(i)*0x100000
		if err := a.mapHost(hostarch.Addr(va), mem[i*pageSize:(i+1)*pageSize], hostarch.ReadWrite); err != nil {
			t.Fatal(err)
		}
		gpas[i], _, _, _ = translate(a, va)
	}
	maps0, unmaps0 := fb.calls()
	slabs := len(p.pool.slabs)

	// A processor that runs the address space must leave the guest before
	// Release returns. The Sentry reuses the pages afterwards.
	v, leave := activeVP(t, p, fb, a)
	done := make(chan struct{})
	go func() {
		as.Release()
		close(done)
	}()
	waitCancels(fb, v, 1)
	select {
	case <-done:
		t.Fatal("Release returned while the processor still ran guest code")
	default:
	}
	leave()
	<-done

	for i := range 4 {
		if _, _, _, ok := translate(a, 0x400000+uint64(i)*0x100000); ok {
			t.Errorf("page %d is still reachable through the page tables after Release", i)
		}
	}
	if !a.dead.Load() {
		t.Error("a released address space is not marked dead")
	}
	if maps, unmaps := fb.calls(); maps != maps0 || unmaps != unmaps0 {
		t.Errorf("Release made %d map calls and %d unmap calls, want none", maps-maps0, unmaps-unmaps0)
	}
	as.Release() // A second Release does nothing.
	if err := a.mapHost(0x400000, mem[:pageSize], hostarch.Read); err == nil {
		t.Error("mapping into a released address space succeeded")
	}
	// The page-table pages return to the pool, so a new address space reuses them.
	b := newTestAS(t, p)
	if len(p.pool.slabs) != slabs {
		t.Errorf("the pool grew from %d to %d slabs", slabs, len(p.pool.slabs))
	}
	if b.id == a.id {
		t.Error("address spaces share an identifier")
	}
	// The new address space reaches no old page until it maps one itself.
	for i := range 4 {
		if _, _, _, ok := translate(b, 0x400000+uint64(i)*0x100000); ok {
			t.Errorf("a new address space inherits the mapping of page %d", i)
		}
	}
	for i, gpa := range gpas {
		if _, ok := hostOf(fb, gpa); !ok {
			t.Errorf("the registration of page %d is gone after Release", i)
		}
	}
}

func TestUnmapOfLargeSparseRanges(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := mustHost(t, fb, 2)
	for i := range 2 {
		if err := as.mapHost(hostarch.Addr(0x400000+uint64(i)*(1<<40)), mem[i*pageSize:(i+1)*pageSize], hostarch.ReadWrite); err != nil {
			t.Fatal(err)
		}
	}
	// A range far larger than the map takes the sparse path.
	as.Unmap(0x400000, 1<<45)
	for i := range 2 {
		if _, _, _, ok := translate(as, 0x400000+uint64(i)*(1<<40)); ok {
			t.Errorf("page %d survives a huge Unmap", i)
		}
	}
	// A range past the user limit clamps instead of wrapping.
	as.Unmap(hostarch.Addr(p.maxUser()-pageSize), 1<<50)
	// A range that starts at or past the user limit does nothing.
	as.Unmap(hostarch.Addr(p.maxUser()), pageSize)
}
