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
	"encoding/binary"
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// A guest store into a composite page faults, because the stub maps the page
// without write access. The Sentry runs the store for the guest. It writes the
// bytes to the file page of the guest page and to the composite page. It then
// moves the program counter past the store. The stub never sees the fault.
//
// A load exclusive does not fault, so the Sentry does not see it. The Sentry
// models the exclusive monitor with the stores that it runs. A store exclusive
// fails when the Sentry ran another store to the same page after the thread
// resumed. The loop of the guest then retries.
//
// Limits of the emulation:
//   - A load exclusive in an earlier run of the thread is not known. A thread
//     that a signal or a preemption interrupts between a load exclusive and its
//     store exclusive can lose an update. This happens when another thread
//     stores to the same word at that time. The host monitor does not survive
//     the interrupt.
//   - An instruction that the emulator does not decode ends in SIGSEGV.
//   - The Sentry runs an atomic operation under the lock of the layer. It is
//     not atomic with a store of another address space that maps the same
//     file page directly.

// storeFaultResult says what the layer did with a fault.
type storeFaultResult int

const (
	// storeFaultIgnored means that the fault is not a guest store that the
	// layer owns. The caller passes it to the memory manager.
	storeFaultIgnored storeFaultResult = iota
	// storeFaultEmulated means that the layer ran the store. The caller
	// resumes the thread.
	storeFaultEmulated
	// storeFaultRefused means that the layer owns the fault but cannot run
	// the store. The caller reports the SIGSEGV to the guest.
	storeFaultRefused
)

// storeEnv gives the store emulator access to a stopped thread and to the
// memory of the guest.
type storeEnv struct {
	ac *arch.Context64
	// fpState is the FP state of the thread in the layout of fpu.State.
	fpState []byte
	// check reports whether the guest can write [addr, addr+n).
	check func(addr uint64, n int) bool
	// read returns n bytes at addr. The check function accepted the range.
	read func(addr uint64, n int) []byte
	// write stores b at addr. The check function accepted the range.
	write func(addr uint64, b []byte)
	// stale reports whether the Sentry ran a store to a page of
	// [addr, addr+n) after the thread resumed. A store exclusive that follows
	// such a store fails. It fails in the same way when another thread changes
	// the word between the load exclusive and the store exclusive.
	stale func(addr uint64, n int) bool
}

// pageLocked returns the block and the index of the guest page that holds
// addr, or false when no page is mapped there.
func (l *subBlockLayer) pageLocked(addr uintptr) (*hostBlock, int, bool) {
	base := subBlockBase(addr)
	hb := l.blocks[base]
	if hb == nil {
		return nil, 0, false
	}
	i := int((addr - base) / hostarch.PageSize)
	return hb, i, hb.subs[i].f != nil
}

// writableLocked reports whether the guest has mapped [addr, addr+n) with
// write access.
func (l *subBlockLayer) writableLocked(addr uint64, n int) bool {
	if n <= 0 || addr+uint64(n) < addr {
		return false
	}
	for p := uintptr(addr) &^ (hostarch.PageSize - 1); p < uintptr(addr)+uintptr(n); p += hostarch.PageSize {
		hb, i, ok := l.pageLocked(p)
		if !ok || !hb.subs[i].at.Write {
			return false
		}
	}
	return true
}

// readLocked reads n bytes at addr from the file pages of the guest. The
// range is mapped.
func (l *subBlockLayer) readLocked(addr uint64, n int) ([]byte, bool) {
	out := make([]byte, 0, n)
	for n > 0 {
		hb, i, ok := l.pageLocked(uintptr(addr))
		if !ok {
			return nil, false
		}
		src, err := hb.subs[i].bytes()
		if err != nil {
			return nil, false
		}
		off := int(addr % hostarch.PageSize)
		chunk := min(n, hostarch.PageSize-off)
		out = append(out, src[off:off+chunk]...)
		addr += uint64(chunk)
		n -= chunk
	}
	return out, true
}

// writeLocked stores b at addr in the file pages of the guest and in the
// composite pages that copy them. The range is writable.
func (l *subBlockLayer) writeLocked(addr uint64, b []byte) {
	for len(b) > 0 {
		hb, i, _ := l.pageLocked(uintptr(addr))
		src, err := hb.subs[i].bytes()
		if err != nil {
			// The check function ran bytes() before. Nothing else changes it.
			panic(err)
		}
		off := int(addr % hostarch.PageSize)
		chunk := min(len(b), hostarch.PageSize-off)
		copy(src[off:], b[:chunk])
		hb.wseq[i] = l.storeSeq.Add(1)
		if hb.hasComp {
			copy(hb.comp.buf[i*hostarch.PageSize+off:], b[:chunk])
		}
		// The guest makes its I-cache maintenance on the page that it maps.
		// The source page can run later through a direct block, and the
		// composite page can run after a change of the permissions.
		flushICache(uintptr(unsafe.Pointer(&src[off])), uintptr(chunk))
		if hb.hasComp {
			flushICache(uintptr(unsafe.Pointer(&hb.comp.buf[i*hostarch.PageSize+off])), uintptr(chunk))
		}
		// Another composite page of this address space can hold the same page.
		sp := &hb.subs[i]
		pageOff := sp.off + uint64(off)
		l.noteHostWrite(sp.f, memmap.FileRange{Start: pageOff, End: pageOff + uint64(chunk)})
		addr += uint64(chunk)
		b = b[chunk:]
	}
}

// staleLocked reports whether the Sentry ran a store to a page of
// [addr, addr+n) with a sequence number above since.
func (l *subBlockLayer) staleLocked(addr uint64, n int, since uint64) bool {
	for p := uintptr(addr) &^ (hostarch.PageSize - 1); p < uintptr(addr)+uintptr(n); p += hostarch.PageSize {
		if hb, i, ok := l.pageLocked(p); ok && hb.wseq[i] > since {
			return true
		}
	}
	return false
}

// emulateStore runs the store that faulted in a composite page.
func (l *subBlockLayer) emulateStore(c *platformContext, ac *arch.Context64) storeFaultResult {
	si := &c.signalInfo
	if si.Signo != int32(linux.SIGSEGV) || si.Code != segvAccerr {
		return storeFaultIgnored
	}
	faultAddr := uintptr(si.Addr())
	l.mu.Lock()
	defer l.mu.Unlock()
	hb, i, ok := l.pageLocked(faultAddr)
	if !ok || hb.cur.kind != stubMapComp || !hb.subs[i].at.Write {
		return storeFaultIgnored
	}
	pc := uint64(ac.IP())
	raw, ok := l.readLocked(pc&^3, 4)
	if !ok || pc&3 != 0 {
		l.logRefusedLocked(pc, 0, "the guest cannot read the instruction")
		return storeFaultRefused
	}
	insn := binary.LittleEndian.Uint32(raw)
	sc := c.sharedContext.Load()
	if sc == nil {
		return storeFaultRefused
	}
	env := storeEnv{
		ac:      ac,
		fpState: sc.shared.FPState[:],
		check: func(addr uint64, n int) bool {
			if !l.writableLocked(addr, n) {
				return false
			}
			// Load the Sentry mappings first, so that a write cannot fail.
			for p := uintptr(addr) &^ (hostarch.PageSize - 1); p < uintptr(addr)+uintptr(n); p += hostarch.PageSize {
				hb, i, _ := l.pageLocked(p)
				if _, err := hb.subs[i].bytes(); err != nil {
					return false
				}
			}
			return true
		},
		read: func(addr uint64, n int) []byte {
			b, _ := l.readLocked(addr, n)
			return b
		},
		write: l.writeLocked,
		stale: func(addr uint64, n int) bool {
			return l.staleLocked(addr, n, c.subBlockSeq)
		},
	}
	if !emulateGuestStore(insn, env) {
		l.logRefusedLocked(pc, insn, "the emulator does not run the instruction or the store is not writable")
		return storeFaultRefused
	}
	ac.SetIP(uintptr(pc + 4))
	return storeFaultEmulated
}

// logRefusedLocked reports a store that the layer cannot run. It logs the
// first refusal of the layer only.
func (l *subBlockLayer) logRefusedLocked(pc uint64, insn uint32, why string) {
	if l.refusedLogged {
		return
	}
	l.refusedLogged = true
	log.Warningf("systrap: cannot run the guest store at pc %#x (instruction %#08x): %s", pc, insn, why)
}
