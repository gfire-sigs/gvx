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

package virtgpu

import (
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/ext/extensions/gpu/client/gpurendertest"
	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/gvx/exttest"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvf"
	"z.gfire.dev/gvx/pkg/usermem"
)

const (
	insnStrX1X0 = 0xf9000001 // STR X1, [X0]
	insnSVC0    = 0xd4000001 // SVC #0
	guestCodeVA = hostarch.Addr(0x400000)
	guestBlobVA = hostarch.Addr(0x10000000)
)

// codeFile is a memmap.File over an anonymous arena that holds guest code.
type codeFile struct {
	memmap.File
	mem []byte
}

func (f *codeFile) MapInternal(fr memmap.FileRange, _ hostarch.AccessType) (safemem.BlockSeq, error) {
	return safemem.BlockSeqOf(safemem.BlockFromSafeSlice(f.mem[fr.Start:fr.End])), nil
}

// guestMM is the platform.MemoryManager of a guest that never faults.
type guestMM struct {
	usermem.IO
	as platform.AddressSpace
}

func (m *guestMM) MMap(context.Context, memmap.MMapOpts) (hostarch.Addr, error) { return 0, nil }
func (m *guestMM) AddressSpace() platform.AddressSpace                          { return m.as }
func (m *guestMM) FindVMAByName(hostarch.AddrRange, string) (hostarch.Addr, uint64, error) {
	return 0, 0, nil
}
func (m *guestMM) WithPinnedMappings(context.Context, hostarch.Addr, int, func(safemem.BlockSeq) error) error {
	return nil
}

// hvfGuest is one hvf address space with a code page that runs
// STR X1, [X0]; SVC #0.
type hvfGuest struct {
	t    *testing.T
	plat *hvf.Platform
	as   platform.AddressSpace
	ctx  platform.Context
}

func newHVFPlatform(t *testing.T) *hvf.Platform {
	t.Helper()
	exttest.RequireHardwareHypervisor(t)
	p, err := hvf.New()
	if err != nil {
		t.Fatalf("hvf.New: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Platform.Close: %v", err)
		}
	})
	return p
}

func newHVFGuest(t *testing.T, p *hvf.Platform) *hvfGuest {
	t.Helper()
	as, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("NewAddressSpace: %v", err)
	}
	code, err := memutil.AllocateAnonymousArena(blobAlignment)
	if err != nil {
		t.Fatalf("AllocateAnonymousArena: %v", err)
	}
	binary.LittleEndian.PutUint32(code[0:], insnStrX1X0)
	binary.LittleEndian.PutUint32(code[4:], insnSVC0)
	if err := as.MapFile(guestCodeVA, &codeFile{mem: code}, memmap.FileRange{Start: 0, End: uint64(hostarch.PageSize)}, hostarch.AccessType{Read: true, Execute: true}, false); err != nil {
		t.Fatalf("MapFile code: %v", err)
	}
	g := &hvfGuest{t: t, plat: p, as: as, ctx: p.NewContext(context.Background())}
	t.Cleanup(func() {
		g.ctx.Release()
		as.Release()
		if err := memutil.UnmapView(code); err != nil {
			t.Errorf("UnmapView: %v", err)
		}
	})
	return g
}

// store64 makes the guest vCPU store v at va.
func (g *hvfGuest) store64(va hostarch.Addr, v uint64) {
	g.t.Helper()
	ac := arch.New(arch.Host)
	ac.SetIP(uintptr(guestCodeVA))
	regs := &ac.StateData().Regs
	regs.Regs[0] = uint64(va)
	regs.Regs[1] = v
	if sig, _, err := g.ctx.Switch(context.Background(), &guestMM{as: g.as}, ac, 0); err != nil || sig != nil {
		g.t.Fatalf("guest store at %#x: signal %+v, error %v", uint64(va), sig, err)
	}
}

// mapBlob maps b at guestBlobVA as mm does: it takes page references on the
// range first.
func (g *hvfGuest) mapBlob(b *blob) memmap.FileRange {
	g.t.Helper()
	fr := memmap.FileRange{Start: 0, End: b.guestSize}
	b.IncRef(fr, 0)
	if err := g.as.MapFile(guestBlobVA, b, fr, hostarch.ReadWrite, false); err != nil {
		g.t.Fatalf("MapFile blob: %v", err)
	}
	return fr
}

func TestBlobGuestStoreReachesSharedMemory(t *testing.T) {
	p := newHVFPlatform(t)
	for _, order := range []string{"unmap then last owner", "last owner then unmap", "producer gone then unmap"} {
		t.Run(order, func(t *testing.T) {
			g := newHVFGuest(t, p)
			base := p.Stage2RegionCount()
			d := newBlobTestDevice(t)
			shm := newTestShm(t, 0x8000)
			b := mustNewBlob(t, d, shm.handle, 0x6000)
			fr := g.mapBlob(b)
			const off, pattern = 0x5008, 0x1122334455667788
			g.store64(guestBlobVA+off, pattern)
			if got := p.Stage2RegionCount(); got != base+1 {
				t.Errorf("Stage2RegionCount while mapped = %d, want %d", got, base+1)
			}
			if got := binary.LittleEndian.Uint64(shm.second[off:]); got != pattern {
				t.Fatalf("second host mapping holds %#x at %#x, want %#x (Stage-2 maps a copy?)", got, off, pattern)
			}
			switch order {
			case "unmap then last owner":
				g.as.Unmap(guestBlobVA, fr.Length())
				b.DecRef(fr)
				b.decOwner()
			case "last owner then unmap":
				b.decOwner()
				if d.BlobBytes() == 0 {
					t.Fatalf("view unmapped while the guest maps it")
				}
				g.store64(guestBlobVA, 1)
				g.as.Unmap(guestBlobVA, fr.Length())
				b.DecRef(fr)
			case "producer gone then unmap":
				shm.unmapSecond(t)
				g.store64(guestBlobVA+off, 2)
				g.as.Unmap(guestBlobVA, fr.Length())
				b.DecRef(fr)
				b.decOwner()
			}
			if got := d.BlobBytes(); got != 0 {
				t.Errorf("BlobBytes = %#x after release, want 0", got)
			}
			if got := p.Stage2RegionCount(); got != base {
				t.Errorf("Stage2RegionCount after release = %d, want %d", got, base)
			}
		})
	}
}

func TestBlobMapUnmapLeavesNoRegion(t *testing.T) {
	p := newHVFPlatform(t)
	g := newHVFGuest(t, p)
	d := newBlobTestDevice(t)
	base := p.Stage2RegionCount()
	for i := 0; i < 2000; i++ {
		shm := newTestShm(t, blobAlignment)
		b := mustNewBlob(t, d, shm.handle, blobAlignment)
		fr := g.mapBlob(b)
		g.store64(guestBlobVA, uint64(i))
		g.as.Unmap(guestBlobVA, fr.Length())
		b.DecRef(fr)
		b.decOwner()
		if got := p.Stage2RegionCount(); got != base {
			t.Fatalf("after blob %d: Stage2RegionCount = %d, want %d", i, got, base)
		}
	}
	if got := d.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes = %d, want 0", got)
	}
}

func mapDupShm(t *testing.T, shm *gpuproto.Blob) []byte {
	t.Helper()
	dup, err := shm.Shm.Dup()
	if err != nil {
		t.Fatalf("Shm.Dup: %v", err)
	}
	defer func() {
		if cerr := dup.Close(); cerr != nil {
			t.Errorf("dup.Close: %v", cerr)
		}
	}()
	raw, err := dup.RawHandle()
	if err != nil {
		t.Fatalf("dup.RawHandle: %v", err)
	}
	view, err := unix.Mmap(int(raw), 0, int(shm.HostSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap dup: %v", err)
	}
	t.Cleanup(func() {
		if uerr := unix.Munmap(view); uerr != nil {
			t.Errorf("Munmap dup: %v", uerr)
		}
	})
	return view
}

func TestBlobFromRendererOnHVF(t *testing.T) {
	client := gpurendertest.New(t)
	p := newHVFPlatform(t)
	g := newHVFGuest(t, p)
	base := p.Stage2RegionCount()
	d := newBlobTestDevice(t)

	if err := client.CreateContext(t.Context(), 1, virtgpuCapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext: %v", err)
	}
	defer func() { _ = client.DestroyContext(1) }()

	res, err := client.CreateBlob(t.Context(), gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     1,
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		BlobID:    0,
		Size:      0x3064,
	})
	if err != nil {
		t.Fatalf("CreateBlob: %v", err)
	}
	if res.HostSize != 0x4000 || res.Shm == nil {
		t.Fatalf("CreateBlob reply = {HostSize:%#x Shm:%v}, want HostSize 0x4000 and non-nil Shm", res.HostSize, res.Shm)
	}
	second := mapDupShm(t, &res)

	b := mustNewBlob(t, d, res.Shm, 0x4000)
	fr := g.mapBlob(b)
	const off, pattern = 0x2008, 0x1122334455667788
	g.store64(guestBlobVA+off, pattern)
	if got := p.Stage2RegionCount(); got != base+1 {
		t.Errorf("Stage2RegionCount while mapped = %d, want %d", got, base+1)
	}
	if got := binary.LittleEndian.Uint64(second[off:]); got != pattern {
		t.Fatalf("second host mapping holds %#x at %#x, want %#x", got, off, pattern)
	}

	g.as.Unmap(guestBlobVA, fr.Length())
	b.DecRef(fr)
	b.decOwner()
	_ = client.UnrefResource(1, 1)

	if got := d.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after release = %#x, want 0", got)
	}
	if got := p.Stage2RegionCount(); got != base {
		t.Errorf("Stage2RegionCount after release = %d, want %d", got, base)
	}
}

func TestBlobFromRendererSurvivesRendererExit(t *testing.T) {
	client := gpurendertest.New(t)
	p := newHVFPlatform(t)
	g := newHVFGuest(t, p)
	base := p.Stage2RegionCount()
	d := newBlobTestDevice(t)

	if err := client.CreateContext(t.Context(), 1, virtgpuCapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext: %v", err)
	}
	res, err := client.CreateBlob(t.Context(), gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     1,
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		BlobID:    0,
		Size:      0x3064,
	})
	if err != nil {
		t.Fatalf("CreateBlob: %v", err)
	}
	second := mapDupShm(t, &res)

	b := mustNewBlob(t, d, res.Shm, 0x4000)
	fr := g.mapBlob(b)

	// Kill the renderer before the guest writes to the blob.
	if err := client.Close(); err != nil {
		t.Fatalf("client.Close: %v", err)
	}

	const (
		off            = 0x1008
		pattern uint64 = 0xfeedfacecafebeef
	)
	g.store64(guestBlobVA+off, pattern)
	if got := binary.LittleEndian.Uint64(second[off:]); got != pattern {
		t.Fatalf("second host mapping after renderer exit = %#x, want %#x", got, pattern)
	}

	g.as.Unmap(guestBlobVA, fr.Length())
	b.DecRef(fr)
	b.decOwner()

	if got := d.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after release = %#x, want 0", got)
	}
	if got := p.Stage2RegionCount(); got != base {
		t.Errorf("Stage2RegionCount after release = %d, want %d", got, base)
	}
}

func TestBlobFromRendererRefusesShortReply(t *testing.T) {
	client := gpurendertest.New(t)
	d := newBlobTestDevice(t)

	if err := client.CreateContext(t.Context(), 1, virtgpuCapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext: %v", err)
	}
	defer func() { _ = client.DestroyContext(1) }()

	res, err := client.CreateBlob(t.Context(), gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     1,
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		BlobID:    0,
		Size:      0x4000,
	})
	if err != nil {
		t.Fatalf("CreateBlob: %v", err)
	}
	defer func() { _ = client.UnrefResource(1, 1) }()

	if _, err := newBlob(d, res.Shm, 0x8000, 0); !errors.Is(err, errBlobSize) {
		t.Fatalf("newBlob(guest 0x8000 on 0x4000 renderer shm) = %v, want errBlobSize", err)
	}
	if got := d.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after refusal = %#x, want 0", got)
	}
	if _, err := res.Shm.RawHandle(); err == nil {
		t.Errorf("newBlob left renderer descriptor open after refusal")
	}
}
