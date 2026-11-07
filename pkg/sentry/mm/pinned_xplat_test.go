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
	"bytes"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/usermem"
)

const pinnedTestAddr = hostarch.Addr(0x20_0000)

// newPinnedTestMM returns a memory manager with one anonymous page at
// pinnedTestAddr.
func newPinnedTestMM(t *testing.T) (context.Context, *MemoryManager) {
	t.Helper()
	mf, err := newCOWTestMemoryFile()
	if err != nil {
		t.Fatalf("newCOWTestMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	ls := linuxLimits(t)
	ctx := context.WithValues(context.Background(), map[any]any{
		pgalloc.CtxMemoryFile: mf,
		limits.CtxLimits:      ls,
	})
	manager, err := NewMemoryManager(faultPlatform{}, mf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SetMmapLayout(arch.New(arch.Host), ls); err != nil {
		t.Fatalf("SetMmapLayout: %v", err)
	}
	if err := mapPinnedTestPage(ctx, manager); err != nil {
		t.Fatal(err)
	}
	return ctx, manager
}

// mapPinnedTestPage maps a new anonymous page at pinnedTestAddr over what is
// there.
func mapPinnedTestPage(ctx context.Context, manager *MemoryManager) error {
	_, err := manager.MMap(ctx, memmap.MMapOpts{
		Addr:     pinnedTestAddr,
		Fixed:    true,
		Unmap:    true,
		Length:   hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.AnyAccess,
		MaxPerms: hostarch.AnyAccess,
	})
	return err
}

func putByte(t *testing.T, ims safemem.BlockSeq, off int, b byte) {
	t.Helper()
	if _, err := safemem.CopySeq(ims.DropFirst(off), safemem.BlockSeqOf(safemem.BlockFromSafeSlice([]byte{b}))); err != nil {
		t.Errorf("write at %d: %v", off, err)
	}
}

// A patch of a system call instruction makes its writes one after the other. A
// thread that replaces the mapping between two writes must not split them
// between the old frame and the new frame.
func TestWithPinnedMappingsDelaysAReplacementOfTheRange(t *testing.T) {
	ctx, manager := newPinnedTestMM(t)
	const length = 8
	inside := make(chan struct{})
	release := make(chan struct{})
	pinnedDone := make(chan error, 1)
	inFrame := make([]byte, length)
	go func() {
		pinnedDone <- manager.WithPinnedMappings(ctx, pinnedTestAddr, length, func(ims safemem.BlockSeq) error {
			putByte(t, ims, 5, 0x06)
			close(inside)
			<-release
			putByte(t, ims, 0, 0xff)
			_, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(inFrame)), ims)
			return err
		})
	}()
	<-inside
	replaced := make(chan struct{})
	go func() {
		defer close(replaced)
		if err := mapPinnedTestPage(ctx, manager); err != nil {
			t.Errorf("MMap over the pinned page: %v", err)
		}
	}()
	select {
	case <-replaced:
		t.Error("the mapping was replaced while a call held its mappings")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-pinnedDone; err != nil {
		t.Fatalf("WithPinnedMappings: %v", err)
	}
	<-replaced

	if want := []byte{0xff, 0, 0, 0, 0, 0x06, 0, 0}; !bytes.Equal(inFrame, want) {
		t.Errorf("the pinned frame holds % x, want % x", inFrame, want)
	}
	got := make([]byte, length)
	if _, err := manager.CopyIn(ctx, pinnedTestAddr, got, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn: %v", err)
	}
	if want := make([]byte, length); !bytes.Equal(got, want) {
		t.Errorf("the new mapping holds % x, want zeroes", got)
	}
}

func TestWithPinnedMappingsFailsOnAnUnmappedRange(t *testing.T) {
	ctx, manager := newPinnedTestMM(t)
	called := false
	// The last 4 bytes of the call lie in the page after the mapping.
	err := manager.WithPinnedMappings(ctx, pinnedTestAddr+hostarch.PageSize-4, 8, func(safemem.BlockSeq) error {
		called = true
		return nil
	})
	if err != linuxerr.EFAULT {
		t.Errorf("WithPinnedMappings = %v, want EFAULT", err)
	}
	if called {
		t.Error("the call ran f on a range that has no mapping")
	}
}
