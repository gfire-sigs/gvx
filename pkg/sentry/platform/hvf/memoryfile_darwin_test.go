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
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// countingBackend counts the Stage-2 calls of a real VM.
type countingBackend struct {
	stage2Backend
	mu           sync.Mutex
	maps, unmaps int
}

func (c *countingBackend) mapHost(host uintptr, ipa uint64, size uintptr) error {
	c.mu.Lock()
	c.maps++
	c.mu.Unlock()
	return c.stage2Backend.mapHost(host, ipa, size)
}

func (c *countingBackend) unmapIPA(ipa uint64, size uintptr) error {
	c.mu.Lock()
	c.unmaps++
	c.mu.Unlock()
	return c.stage2Backend.unmapIPA(ipa, size)
}

func (c *countingBackend) counts() (maps, unmaps int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maps, c.unmaps
}

// A guest maps and uses 4 MiB of a real pgalloc.MemoryFile. The Stage-2 call
// count stays at one for the chunk while the guest maps, unmaps and remaps the
// range. The Sentry writes through its own mapping of the memory file, and the
// guest sees the write.
func TestMemoryFileRangeUsesOneStage2RegionOnARealVM(t *testing.T) {
	plat := newTestPlatform(t)
	counter := &countingBackend{stage2Backend: hvBackend{}}
	plat.vm.regions.setBackend(counter)

	mf, err := pgalloc.NewDefaultMemoryFile(pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()
	const size = 4 << 20
	fr, err := mf.Allocate(size, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil || bs.NumBlocks() != 1 {
		t.Fatalf("MapInternal = (%d blocks, %v), want one block", bs.NumBlocks(), err)
	}
	host := bs.Head().ToSlice()
	binary.LittleEndian.PutUint64(host[0:], 0x1001)
	binary.LittleEndian.PutUint64(host[size-8:], 0x2002)

	const insnStrX3X2 uint32 = 0xf9000043
	g := newGuest(t, plat, insnLdrX1X0, insnStrX3X2, insnSVC0)
	baseMaps, _ := counter.counts()
	const va = hostarch.Addr(0x4000_0000)
	if err := g.as.MapFile(va, mf, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatalf("MapFile: %v", err)
	}
	if maps, _ := counter.counts(); maps-baseMaps != 1 {
		t.Errorf("MapFile of 4 MiB made %d hv_vm_map calls, want 1", maps-baseMaps)
	}
	// LDR X1,[X0]; STR X3,[X2]; SVC #0 in the guest: the store hits the middle of the range.
	g.regs().Regs[2], g.regs().Regs[3] = uint64(va)+size/2, 0x3003
	for _, c := range []struct {
		off  uint64
		want uint64
	}{{0, 0x1001}, {size - 8, 0x2002}} {
		if got, sig, err := g.read64(va + hostarch.Addr(c.off)); sig != nil || err != nil || got != c.want {
			t.Fatalf("the guest read (%#x, %v, %v) at +%#x, want %#x", got, sig, err, c.off, c.want)
		}
	}

	// The Sentry reads the guest store through the memory file mapping.
	if got := binary.LittleEndian.Uint64(host[size/2:]); got != 0x3003 {
		t.Fatalf("the memory file holds %#x, want the guest store 0x3003", got)
	}

	maps0, unmaps0 := counter.counts()
	for range 5 {
		g.as.Unmap(va, size)
		if err := g.as.MapFile(va, mf, fr, hostarch.ReadWrite, false); err != nil {
			t.Fatal(err)
		}
	}
	g.as.Unmap(va, size)
	if maps, unmaps := counter.counts(); maps != maps0 || unmaps != unmaps0 {
		t.Errorf("five unmap and remap rounds made %d hv_vm_map and %d hv_vm_unmap calls, want 0 and 0", maps-maps0, unmaps-unmaps0)
	}
	// Release drops the arena region of the guest. The memory file region stays.
	g.as.Release()
	if maps, unmaps := counter.counts(); maps != maps0 || unmaps != unmaps0+1 {
		t.Errorf("Release made %d hv_vm_map and %d hv_vm_unmap calls, want 0 and 1", maps-maps0, unmaps-unmaps0)
	}
}

func TestReusedHostVirtualAddressMapsNewPhysicalPageOnARealVM(t *testing.T) {
	plat := newTestPlatform(t)
	counter := &countingBackend{stage2Backend: hvBackend{}}
	plat.vm.regions.setBackend(counter)

	slot, err := unix.Mmap(-1, 0, hostPageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Munmap(slot); err != nil {
			t.Errorf("Munmap: %v", err)
		}
	})
	baseAddr := uintptr(unsafe.Pointer(&slot[0]))

	const (
		valA = uint64(0xAAAA_1111_2222_3333)
		valB = uint64(0xBBBB_4444_5555_6666)
		va   = hostarch.Addr(0x5000_0000)
	)
	binary.LittleEndian.PutUint64(slot[:8], valA)

	fileA := &testFile{mem: slot[:pageSize4K]}
	g1 := newGuest(t, plat, insnLdrX1X0, insnSVC0)
	maps0, unmaps0 := counter.counts()
	if err := g1.as.MapFile(va, fileA, memmap.FileRange{Start: 0, End: pageSize4K}, hostarch.ReadWrite, false); err != nil {
		t.Fatalf("MapFile fileA: %v", err)
	}
	if maps, _ := counter.counts(); maps != maps0+1 {
		t.Fatalf("MapFile fileA made %d hv_vm_map calls, want 1", maps-maps0)
	}
	if got, sig, err := g1.read64(va); sig != nil || err != nil || got != valA {
		t.Fatalf("guest read fileA = (%#x, %v, %v), want %#x", got, sig, err, valA)
	}

	// Release g1 so both its arena region and fileA drop to zero references and
	// unmap from Stage-2 IPA space.
	g1.as.Release()
	if _, unmaps := counter.counts(); unmaps != unmaps0+2 {
		t.Fatalf("Release after fileA made %d hv_vm_unmap calls, want 2", unmaps-unmaps0)
	}

	// Atomically replace the backing physical page at baseAddr via MAP_FIXED.
	mappedAddr, _, errno := unix.Syscall6(
		unix.SYS_MMAP,
		baseAddr,
		uintptr(hostPageSize),
		uintptr(unix.PROT_READ|unix.PROT_WRITE),
		uintptr(unix.MAP_ANON|unix.MAP_PRIVATE|unix.MAP_FIXED),
		^uintptr(0),
		0,
	)
	if errno != 0 || mappedAddr != baseAddr {
		t.Fatalf("MAP_FIXED remap at %#x returned (%#x, %v)", baseAddr, mappedAddr, errno)
	}
	if got := binary.LittleEndian.Uint64(slot[:8]); got != 0 {
		t.Fatalf("fresh MAP_FIXED page held %#x, want 0", got)
	}
	binary.LittleEndian.PutUint64(slot[:8], valB)

	fileB := &testFile{mem: slot[:pageSize4K]}
	g2 := newGuest(t, plat, insnLdrX1X0, insnSVC0)
	maps1, _ := counter.counts()
	if err := g2.as.MapFile(va, fileB, memmap.FileRange{Start: 0, End: pageSize4K}, hostarch.ReadWrite, false); err != nil {
		t.Fatalf("MapFile fileB: %v", err)
	}
	if maps, _ := counter.counts(); maps != maps1+1 {
		t.Fatalf("MapFile fileB at reused host VA made %d hv_vm_map calls, want 1", maps-maps1)
	}
	if got, sig, err := g2.read64(va); sig != nil || err != nil || got != valB {
		t.Fatalf("guest read fileB = (%#x, %v, %v), want %#x", got, sig, err, valB)
	}
}
