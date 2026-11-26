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

package mm

import (
	"runtime"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/usermem"
)

// mmCopyContext implements marshal.CopyContext against a MemoryManager.
type mmCopyContext struct {
	ctx context.Context
	mm  *MemoryManager
}

func (c *mmCopyContext) CopyScratchBuffer(size int) []byte {
	return make([]byte, size)
}

func (c *mmCopyContext) CopyOutBytes(addr hostarch.Addr, b []byte) (int, error) {
	return c.mm.CopyOut(c.ctx, addr, b, usermem.IOOpts{})
}

func (c *mmCopyContext) CopyInBytes(addr hostarch.Addr, b []byte) (int, error) {
	return c.mm.CopyIn(c.ctx, addr, b, usermem.IOOpts{})
}

// stackGrowMappable forces goroutine stack reallocation and GC inside Translate
// so any heap-escaped closure holding a gohacks.Noescape stack pointer fails
// deterministically.
type stackGrowMappable struct {
	memmap.MappableNoHugepages
	mf    *pgalloc.MemoryFile
	start uint64
}

func (m *stackGrowMappable) AddMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, uint64, bool) error {
	return nil
}

func (m *stackGrowMappable) RemoveMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, uint64, bool) {
}

func (m *stackGrowMappable) CopyMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, hostarch.AddrRange, uint64, bool) error {
	return nil
}

//go:noinline
func forceStackGrowth(depth int, acc byte) byte {
	var frame [256]byte
	frame[0] = acc ^ byte(depth)
	if depth <= 0 {
		runtime.GC()
		return frame[0]
	}
	return forceStackGrowth(depth-1, frame[0])
}

func (m *stackGrowMappable) Translate(_ context.Context, required, _ memmap.MappableRange, _ hostarch.AccessType) ([]memmap.Translation, error) {
	_ = forceStackGrowth(64, byte(required.Start))
	return []memmap.Translation{{
		Source: required,
		File:   m.mf,
		Offset: m.start + required.Start,
		Perms:  hostarch.ReadWrite,
	}}, nil
}

func (m *stackGrowMappable) InvalidateUnsavable(context.Context) error { return nil }

// TestCopyOutAndCopyInNoescapeAcrossStackGrowth verifies that CopyOut and
// CopyIn keep their internal-mapping closures on the stack so real
// gohacks.Noescape callers (linux.SignalStack.CopyOut and CopyIn) stay valid
// across goroutine stack growth and GC.
func TestCopyOutAndCopyInNoescapeAcrossStackGrowth(t *testing.T) {
	mf, err := newCOWTestMemoryFile()
	if err != nil {
		t.Fatalf("newCOWTestMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	page := uint64(hostarch.PageSize)
	fr, err := mf.Allocate(2*page, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	ls := linuxLimits(t)
	ctx := context.WithValues(context.Background(), map[any]any{
		pgalloc.CtxMemoryFile: mf,
		limits.CtxLimits:      ls,
	})
	manager, err := NewMemoryManager(faultPlatform{}, mf)
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	if _, err := manager.SetMmapLayout(arch.New(arch.Host), ls); err != nil {
		t.Fatalf("SetMmapLayout: %v", err)
	}
	addr, err := manager.MMap(ctx, memmap.MMapOpts{
		Length:   2 * page,
		Mappable: &stackGrowMappable{mf: mf, start: fr.Start},
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.ReadWrite,
	})
	if err != nil {
		t.Fatalf("MMap: %v", err)
	}

	cc := &mmCopyContext{ctx: ctx, mm: manager}
	want := linux.SignalStack{
		Addr:  0x1122334455667788,
		Flags: linux.SS_DISABLE,
		Size:  0x2000,
	}

	// CopyOut in a fresh goroutine (minimal initial stack) onto page 0.
	errCh := make(chan error, 1)
	go func() {
		src := want
		_, err := src.CopyOut(cc, addr)
		errCh <- err
	}()
	if err := <-errCh; err != nil {
		t.Fatalf("SignalStack.CopyOut: %v", err)
	}

	var readBack linux.SignalStack
	if _, err := readBack.CopyIn(cc, addr); err != nil {
		t.Fatalf("SignalStack.CopyIn readback: %v", err)
	}
	if readBack != want {
		t.Fatalf("CopyOut produced %+v, want %+v", readBack, want)
	}

	// Seed page 1 via a plain slice write, then run SignalStack.CopyIn from a
	// fresh goroutine so Translate forces stack growth while CopyIn holds a
	// gohacks.Noescape stack pointer into dst.
	page1 := addr + hostarch.Addr(page)
	seed := make([]byte, want.SizeBytes())
	want.MarshalUnsafe(seed)
	if _, err := manager.CopyOut(ctx, page1, seed, usermem.IOOpts{}); err != nil {
		t.Fatalf("seed page 1: %v", err)
	}

	// Unmap and remap page 1 so CopyIn takes the slow path through Translate.
	if err := manager.MUnmap(ctx, page1, page); err != nil {
		t.Fatalf("MUnmap page 1: %v", err)
	}
	if _, err := manager.MMap(ctx, memmap.MMapOpts{
		Addr:     page1,
		Fixed:    true,
		Length:   page,
		Mappable: &stackGrowMappable{mf: mf, start: fr.Start + page},
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.ReadWrite,
	}); err != nil {
		t.Fatalf("remap page 1: %v", err)
	}

	type copyInResult struct {
		got linux.SignalStack
		err error
	}
	inCh := make(chan copyInResult, 1)
	go func() {
		var dst linux.SignalStack
		_, err := dst.CopyIn(cc, page1)
		inCh <- copyInResult{got: dst, err: err}
	}()
	res := <-inCh
	if res.err != nil {
		t.Fatalf("SignalStack.CopyIn: %v", res.err)
	}
	if res.got != want {
		t.Fatalf("CopyIn produced %+v, want %+v", res.got, want)
	}
}
