//go:build windows

package pgalloc

import (
	"bytes"
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/usage"
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
	// DiscardVirtualMemory can return ERROR_INVALID_PARAMETER on mapped section views,
	// while DecommitSharedPages must still zero the shared backing pages.
	if err := DecommitSharedPages(pages); err != nil && !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			t.Fatalf("DecommitSharedPages returned non-Errno error: %v", err)
		}
		t.Fatalf("DecommitSharedPages = %v, want nil or ERROR_INVALID_PARAMETER", err)
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
	// Verify that both views remain coherent after decommit.
	alias[0] = 0xA5
	alias[len(alias)-1] = 0x3C
	if pages[0] != 0xA5 || pages[len(pages)-1] != 0x3C {
		t.Fatalf("pages bytes after alias write = %#x..%#x, want 0xA5..0x3C", pages[0], pages[len(pages)-1])
	}
}

func TestDecommitSharedPagesKeepsNeighbours(t *testing.T) {
	t.Parallel()
	pages, err := AllocateSharedPages(3 * 4096)
	if err != nil {
		t.Fatalf("AllocateSharedPages: %v", err)
	}
	defer func() {
		if err := ReleaseSharedPages(pages); err != nil {
			t.Errorf("ReleaseSharedPages: %v", err)
		}
	}()
	for i := range pages {
		pages[i] = 0xC3
	}
	const page = 4096
	if err := DecommitSharedPages(pages[page : 2*page]); err != nil && !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		t.Fatalf("DecommitSharedPages: %v", err)
	}
	for i, b := range pages {
		want := byte(0xC3)
		if i >= page && i < 2*page {
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

func TestDefaultMemoryFileDecommitZeroesPages(t *testing.T) {
	t.Parallel()
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	allocSize := uint64(2 * hostarch.PageSize)
	fr, err := mf.Allocate(allocSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if fr.Length() != allocSize {
		t.Fatalf("fr.Length() = %d, want %d", fr.Length(), allocSize)
	}
	if !mf.HasUniqueRef(fr) {
		t.Fatalf("HasUniqueRef(%v) = false, want true", fr)
	}
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if uint64(bs.NumBytes()) != allocSize {
		t.Fatalf("MapInternal NumBytes = %d, want %d", bs.NumBytes(), allocSize)
	}
	slice := bs.Head().ToSlice()
	for i := range slice {
		slice[i] = 0x7F
	}
	// NTFS refuses to zero a range that a view maps, so Decommit may take its manual-zero path.
	mf.Decommit(fr)
	for i, b := range slice {
		if b != 0 {
			t.Fatalf("slice[%d] = %#x after Decommit, want 0", i, b)
		}
	}
	// Verify that the mapping remains writable and visible across a second MapInternal call.
	slice[0] = 0x42
	slice[len(slice)-1] = 0x99
	bs2, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatalf("second MapInternal: %v", err)
	}
	slice2 := bs2.Head().ToSlice()
	if slice2[0] != 0x42 || slice2[len(slice2)-1] != 0x99 {
		t.Fatalf("second MapInternal bytes = %#x..%#x, want 0x42..0x99", slice2[0], slice2[len(slice2)-1])
	}
	mf.DecRef(fr)
}

func BenchmarkAllocateAndDecommitSharedPages(b *testing.B) {
	const regionSize = 16 * 4096
	pages, err := AllocateSharedPages(regionSize)
	if err != nil {
		b.Fatalf("AllocateSharedPages: %v", err)
	}
	defer func() {
		if err := ReleaseSharedPages(pages); err != nil {
			b.Fatalf("ReleaseSharedPages: %v", err)
		}
	}()
	b.SetBytes(regionSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pages[0] = byte(i)
		pages[len(pages)-1] = byte(i)
		if err := DecommitSharedPages(pages); err != nil && !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			b.Fatalf("DecommitSharedPages: %v", err)
		}
	}
}

func BenchmarkMemoryFileAllocateMapDecommit(b *testing.B) {
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		b.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	allocSize := uint64(4 * hostarch.PageSize)
	b.SetBytes(int64(allocSize))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fr, err := mf.Allocate(allocSize, AllocOpts{Kind: usage.Anonymous})
		if err != nil {
			b.Fatalf("Allocate: %v", err)
		}
		bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
		if err != nil {
			b.Fatalf("MapInternal: %v", err)
		}
		head := bs.Head().ToSlice()
		head[0] = byte(i)
		mf.Decommit(fr)
		mf.DecRef(fr)
	}
}

func TestWindowsMultiChunkLoadFromAndDestroyReleasesKernelViews(t *testing.T) {
	const (
		winMemFree    = 0x10000 // MEM_FREE from winnt.h
		winMemPrivate = 0x20000 // MEM_PRIVATE from winnt.h
		winMemMapped  = 0x40000 // MEM_MAPPED from winnt.h
	)
	for _, tc := range []struct {
		name          string
		sharedSection bool
		wantType      uint32
	}{
		{name: "private", sharedSection: false, wantType: winMemPrivate},
		{name: "shared_section", sharedSection: true, wantType: winMemMapped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fx := buildMultiChunkFixture(t)

			var buf bytes.Buffer
			if err := fx.mf.SaveTo(ctx, &buf, &SaveOpts{ExcludeCommittedZeroPages: true}); err != nil {
				t.Fatalf("SaveTo: %v", err)
			}

			restored := newTestMemoryFile(t, MemoryFileOpts{
				ExpectHugepages: true,
				SharedSection:   tc.sharedSection,
			})
			if err := restored.LoadFrom(ctx, &buf, &LoadOpts{}); err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			chunks := append([]chunkInfo(nil), restored.chunksLoad()...)
			if len(chunks) < 2 {
				t.Fatalf("len(chunks) = %d, want >= 2", len(chunks))
			}
			for i, c := range chunks {
				var info windows.MemoryBasicInformation
				if err := windows.VirtualQuery(c.mapping, &info, unsafe.Sizeof(info)); err != nil {
					t.Fatalf("VirtualQuery(chunk %d at %#x): %v", i, c.mapping, err)
				}
				if (info.State != windows.MEM_COMMIT && info.State != windows.MEM_RESERVE) || info.Type != tc.wantType || info.AllocationBase != c.mapping {
					t.Fatalf("chunk %d before Destroy: State=%#x Type=%#x AllocationBase=%#x, want MEM_COMMIT/MEM_RESERVE Type=%#x at %#x",
						i, info.State, info.Type, info.AllocationBase, tc.wantType, c.mapping)
				}
			}

			fx.verifyMemoryFile(t, restored)
			fx.releaseAndDestroy(t, restored)

			for i, c := range chunks {
				// Another runtime VirtualAlloc call can claim the lowest freed VA hole
				// before VirtualQuery runs. Sum contiguous sub-regions sharing the
				// chunk AllocationBase so a leaked chunk split between MEM_COMMIT and
				// MEM_RESERVE sub-regions is still caught.
				var surviving uintptr
				for cur := c.mapping; cur < c.mapping+chunkSize; {
					var info windows.MemoryBasicInformation
					if err := windows.VirtualQuery(cur, &info, unsafe.Sizeof(info)); err != nil {
						t.Fatalf("VirtualQuery(chunk %d at %#x after Destroy): %v", i, cur, err)
					}
					if info.State == winMemFree || info.Type != tc.wantType || info.AllocationBase != c.mapping || info.RegionSize == 0 {
						break
					}
					surviving += info.RegionSize
					cur = info.BaseAddress + info.RegionSize
				}
				if surviving >= chunkSize {
					t.Fatalf("chunk %d still mapped after Destroy: surviving=%#x Type=%#x AllocationBase=%#x",
						i, surviving, tc.wantType, c.mapping)
				}
			}

			fx.releaseAndDestroy(t, fx.mf)
		})
	}
}

type processMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  byte
	Directory      byte
	_              [2]byte
}

var procGetProcessMemoryInfo = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")

func queryProcessMemory(t *testing.T) processMemoryCountersEx {
	t.Helper()
	var pmc processMemoryCountersEx
	pmc.CB = uint32(unsafe.Sizeof(pmc))
	r1, _, err := procGetProcessMemoryInfo.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&pmc)),
		uintptr(pmc.CB),
	)
	if r1 == 0 {
		t.Fatalf("K32GetProcessMemoryInfo: %v", err)
	}
	return pmc
}

func queryFileStandardInfo(t *testing.T, h windows.Handle) fileStandardInfo {
	t.Helper()
	var info fileStandardInfo
	if err := windows.GetFileInformationByHandleEx(
		h,
		windows.FileStandardInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		t.Fatalf("GetFileInformationByHandleEx(FileStandardInfo): %v", err)
	}
	return info
}

func waitReleaserIdle(t *testing.T, mf *MemoryFile) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		mf.mu.Lock()
		busy := mf.haveWaste
		mf.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("releaser did not drain waste within 20s")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWindowsMemoryFileReclaimsWorkingSetAndUsesZeroDisk(t *testing.T) {
	const allocBytes = uint64(128 << 20)
	for _, tc := range []struct {
		name           string
		sharedSection  bool
		checkCommitDec bool
	}{
		{name: "private", sharedSection: false, checkCommitDec: true},
		{name: "shared_section", sharedSection: true, checkCommitDec: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mf, err := NewDefaultMemoryFile(MemoryFileOpts{
				DisableMemoryAccounting: true,
				SharedSection:           tc.sharedSection,
			})
			if err != nil {
				t.Fatalf("NewDefaultMemoryFile: %v", err)
			}
			defer mf.Destroy()

			fr, err := mf.Allocate(allocBytes, AllocOpts{Kind: usage.Anonymous})
			if err != nil {
				t.Fatalf("Allocate(%d): %v", allocBytes, err)
			}
			bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
			if err != nil {
				t.Fatalf("MapInternal: %v", err)
			}
			slice := bs.Head().ToSlice()
			for i := 0; i < len(slice); i += int(hostarch.PageSize) {
				slice[i] = 0x5A
			}

			finfo := queryFileStandardInfo(t, windows.Handle(mf.FD()))
			if finfo.EndOfFile != 0 || finfo.AllocationSize != 0 {
				t.Fatalf("backing temp file grew on disk: EndOfFile=%d AllocationSize=%d, want (0, 0)",
					finfo.EndOfFile, finfo.AllocationSize)
			}

			// AllocateAndCommit must also keep the placeholder file at zero bytes.
			frCommit, err := mf.Allocate(uint64(hostarch.PageSize), AllocOpts{
				Kind: usage.Anonymous,
				Mode: AllocateAndCommit,
			})
			if err != nil {
				t.Fatalf("Allocate(AllocateAndCommit): %v", err)
			}
			finfoCommit := queryFileStandardInfo(t, windows.Handle(mf.FD()))
			mf.DecRef(frCommit)
			if finfoCommit.EndOfFile != 0 || finfoCommit.AllocationSize != 0 {
				t.Fatalf("backing temp file grew after AllocateAndCommit: EndOfFile=%d AllocationSize=%d, want (0, 0)",
					finfoCommit.EndOfFile, finfoCommit.AllocationSize)
			}

			before := queryProcessMemory(t)
			mf.DecRef(fr)
			waitReleaserIdle(t, mf)
			after := queryProcessMemory(t)

			t.Logf("%s: WorkingSet %d MiB -> %d MiB, PrivateUsage %d MiB -> %d MiB",
				tc.name,
				before.WorkingSetSize>>20, after.WorkingSetSize>>20,
				before.PrivateUsage>>20, after.PrivateUsage>>20,
			)

			const minDrop = uintptr(allocBytes / 2)
			if before.WorkingSetSize <= after.WorkingSetSize || before.WorkingSetSize-after.WorkingSetSize < minDrop {
				t.Fatalf("WorkingSetSize did not drop after DecRef: before=%d MiB after=%d MiB (want drop >= %d MiB)",
					before.WorkingSetSize>>20, after.WorkingSetSize>>20, minDrop>>20)
			}
			if tc.checkCommitDec {
				if before.PrivateUsage <= after.PrivateUsage || before.PrivateUsage-after.PrivateUsage < minDrop {
					t.Fatalf("PrivateUsage (commit charge) did not drop after DecRef: before=%d MiB after=%d MiB (want drop >= %d MiB)",
						before.PrivateUsage>>20, after.PrivateUsage>>20, minDrop>>20)
				}
			}

			// Re-allocate and verify every returned page reads as zero.
			fr2, err := mf.Allocate(allocBytes, AllocOpts{Kind: usage.Anonymous})
			if err != nil {
				t.Fatalf("second Allocate: %v", err)
			}
			defer mf.DecRef(fr2)
			bs2, err := mf.MapInternal(fr2, hostarch.Read)
			if err != nil {
				t.Fatalf("second MapInternal: %v", err)
			}
			slice2 := bs2.Head().ToSlice()
			for i := 0; i < len(slice2); i += int(hostarch.PageSize) {
				if slice2[i] != 0 {
					t.Fatalf("re-allocated page offset %#x = %#x, want 0", i, slice2[i])
				}
			}
		})
	}
}
