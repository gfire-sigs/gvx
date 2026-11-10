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

package pgalloc

import (
	"runtime"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

const (
	// maxCoalescedScanWindow is the largest range that coalesceScanRangeLocked
	// merges into one mincore call (16 MiB = 4096 4 KB pages).
	maxCoalescedScanWindow = 16 << 20

	// maxCoalescedScanBridge is the largest committed or releasing gap that
	// coalesceScanRangeLocked bridges between two uncommitted segments.
	maxCoalescedScanBridge = 64 << 10
)

// canSkipUsageScan reports whether UpdateUsage may skip its scan because the
// usage of the memory file equals the committed bytes that it already knows.
// The usage is the block count of the file. Linux updates the count when a
// page commits. macOS updates it late, by up to 15 seconds in a measurement.
// A host with pages larger than 4 KB commits a whole host page when one guest
// sub-page faults. The scan for memory cgroups therefore runs whenever the
// host page exceeds 4 KB or the host is neither Linux nor Android.
func canSkipUsageScan(memCgIDs map[uint32]struct{}) bool {
	if memCgIDs == nil {
		return true
	}
	if unix.Getpagesize() > hostarch.PageSize {
		return false
	}
	return runtime.GOOS == "linux" || runtime.GOOS == "android"
}

// mincoreGuestPages queries the residency of s and writes one byte for each
// 4 KB guest page (hostarch.PageSize) into buf. On Linux and Android kernels
// with a larger host page, raw SYS_MINCORE requires a host-page-aligned start
// address and writes one byte per host page. mincoreGuestPages queries the
// enclosing host pages and copies each host-page result to its guest sub-pages.
func mincoreGuestPages(s, buf []byte) error {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		if hostPage := uintptr(unix.Getpagesize()); hostPage > hostarch.PageSize {
			return mincoreExpandHostPages(s, buf, hostPage, rawMincore)
		}
	}
	return mincore(s, buf)
}

func rawMincore(base, span uintptr, vec []byte) error {
	if _, _, errno := unix.RawSyscall(
		unix.SYS_MINCORE,
		base,
		span,
		uintptr(unsafe.Pointer(&vec[0]))); errno != 0 {
		return errno
	}
	return nil
}

func mincoreExpandHostPages(s, buf []byte, hostPage uintptr, query func(base, span uintptr, vec []byte) error) error {
	if len(s) == 0 {
		return nil
	}
	addr := uintptr(unsafe.Pointer(&s[0]))
	if addr&(hostarch.PageSize-1) != 0 {
		return unix.EINVAL
	}
	length := uintptr(len(s))
	base := addr &^ (hostPage - 1)
	span := (addr + length - base + hostPage - 1) &^ (hostPage - 1)
	resident := make([]byte, span/hostPage)
	if err := query(base, span, resident); err != nil {
		return err
	}
	pages := int((length + hostarch.PageSize - 1) / hostarch.PageSize)
	for i := range pages {
		buf[i] = resident[(addr-base+uintptr(i)*hostarch.PageSize)/hostPage]
	}
	return nil
}

// FlushCommitScan waits for any in-flight scan, clears the scan rate limit,
// and completes an immediate scan when f has a backing file before the caller
// parks on kernel inactivity.
func (f *MemoryFile) FlushCommitScan() {
	for spins := 0; ; spins++ {
		f.mu.Lock()
		if !f.ongoingCommitScan.Load() {
			f.nextCommitScan = time.Time{}
			if f.file != nil && !f.isSaving && !f.opts.DisableMemoryAccounting {
				startTime := time.Now()
				f.ongoingCommitScan.Store(true)
				_ = f.updateUsageLocked(nil)
				f.ongoingCommitScan.Store(false)
				scanTime := time.Since(startTime)
				f.nextCommitScan = startTime.Add(max(linux.ClockTick, scanTime*commitScanIntervalRatio))
			}
			f.mu.Unlock()
			return
		}
		f.mu.Unlock()
		if spins < 4 {
			runtime.Gosched()
		} else {
			time.Sleep(time.Millisecond)
		}
	}
}

// coalesceScanRangeLocked extends the scan range of maseg across subsequent
// uncommitted segments in the same 16 MiB window and chunk, bridging committed
// gaps of up to 64 KiB so sparse page faults do not issue thousands of
// single-segment mincore calls.
//
// +checklocks:f.mu
func (f *MemoryFile) coalesceScanRangeLocked(maseg memAcctIterator, unscannedStart uint64, memCgIDs map[uint32]struct{}) memmap.FileRange {
	fr := maseg.Range()
	if fr.Start < unscannedStart {
		fr.Start = unscannedStart
	}
	chunkEnd := (fr.Start &^ chunkMask) + chunkSize
	maxEnd := min(chunkEnd, fr.Start+maxCoalescedScanWindow)
	if fr.End >= maxEnd {
		fr.End = maxEnd
		return fr
	}
	for seg := maseg.NextSegment(); seg.Ok() && seg.Start() < maxEnd; seg = seg.NextSegment() {
		ma := seg.ValuePtr()
		needsScan := !ma.wasteOrReleasing && !ma.knownCommitted
		if needsScan && memCgIDs != nil {
			_, needsScan = memCgIDs[ma.memCgID]
		}
		if needsScan {
			fr.End = min(seg.End(), maxEnd)
			if seg.End() >= maxEnd {
				break
			}
			continue
		}
		if seg.End() > maxEnd || seg.Range().Length() > maxCoalescedScanBridge {
			break
		}
	}
	return fr
}

// Accounting returns the memory usage accounting that f charges. It is
// MemoryFileOpts.Accounting, or usage.MemoryAccounting when the option is nil.
// A reader of the usage of one sandbox, such as /proc/meminfo or memory.current,
// must read the accounting of the memory file of that sandbox. The global
// usage.MemoryAccounting sums the memory of every kernel of the process.
func (f *MemoryFile) Accounting() *usage.MemoryLocked {
	if f.opts.Accounting != nil {
		return f.opts.Accounting
	}
	return usage.MemoryAccounting
}
