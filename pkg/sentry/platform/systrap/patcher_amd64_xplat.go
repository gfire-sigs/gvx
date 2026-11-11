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

//go:build darwin || windows

package systrap

import (
	"fmt"
	"sort"

	"golang.org/x/arch/x86/x86asm"
)

// The amd64 patcher rewrites two instruction classes of a Linux guest.
//
// Windows does not trap SYSCALL, so each SYSCALL becomes INT3 followed by NOP.
// The debugger receives EXCEPTION_BREAKPOINT with RIP one byte after the site.
// Windows resets the FS base on a context switch, so RDFSBASE reads zero.
// Each RDFSBASE becomes INT3 followed by NOPs, and the debugger emulates it.
//
// The bytes 0F 05 also occur inside other instructions, for example inside an
// immediate or a displacement. A byte search is therefore not safe. The scan
// decodes the page and keeps only the instructions that start at a boundary.

// amd64SiteKind names what a scanned amd64 instruction is.
type amd64SiteKind uint8

const (
	// amd64SiteSyscall is SYSCALL, bytes 0F 05.
	amd64SiteSyscall amd64SiteKind = iota + 1
	// amd64SiteRDFSBASE is RDFSBASE r32 or r64, bytes F3 [REX] 0F AE /0 with
	// mod=11.
	amd64SiteRDFSBASE
	// amd64SiteRDGSBASE is RDGSBASE r32 or r64, bytes F3 [REX] 0F AE /1 with
	// mod=11.
	amd64SiteRDGSBASE
	// amd64SiteWRFSBASE is WRFSBASE r32 or r64, bytes F3 [REX] 0F AE /2 with
	// mod=11.
	amd64SiteWRFSBASE
	// amd64SiteWRGSBASE is WRGSBASE r32 or r64, bytes F3 [REX] 0F AE /3 with
	// mod=11.
	amd64SiteWRGSBASE
	// amd64SiteGSMem is a memory instruction with a GS segment override prefix.
	amd64SiteGSMem
	// amd64SiteInt2E is INT 0x2E, bytes CD 2E, which enters the Windows NT
	// kernel service gate on x64 hosts and raises SIGSEGV on Linux.
	amd64SiteInt2E
	// amd64SiteSysenter is SYSENTER, bytes 0F 34, which raises SIGILL on
	// 64-bit Linux.
	amd64SiteSysenter
	// amd64SiteGuardedInsn marks the start of an outer instruction whose
	// interior or trailing boundary holds a raw kernel-entry byte pair. Both
	// the outer start and the interior exit offset carry INT3 so normal
	// execution emulates the outer instruction while a mid-instruction branch
	// traps in the Sentry.
	amd64SiteGuardedInsn
)

const (
	// amd64PageSize is the page size of the Windows engine.
	amd64PageSize = 4096

	// amd64MaxInsnLen is the longest amd64 instruction in bytes. It sets the
	// context that the scan needs on each side of a page.
	amd64MaxInsnLen = 15

	// amd64SweepCount is the number of linear decode sweeps of one scan.
	amd64SweepCount = amd64MaxInsnLen + 1

	// amd64ScanLead is the number of bytes before a page that the patcher
	// gives the scan. The sweeps start at the first 16 of them, so that a
	// sweep that starts inside an instruction finds the real boundaries before
	// it reaches the page. With only 15 bytes, the wrong sweeps of a page of
	// Node.js 20 out-voted the right ones and found a GS instruction inside a
	// `lea`.
	amd64ScanLead = 64

	// amd64INT3 and amd64NOP are the filler opcodes of a patched site.
	amd64INT3 = 0xCC
	amd64NOP  = 0x90

	// amd64SiteBeforePage is the Offset of a site whose first byte lies in the
	// last byte of the previous page, and whose second byte is page[0].
	amd64SiteBeforePage = -1
)

// amd64Trap is written over every SYSCALL site: INT3 then NOP. The debugger
// sees EXCEPTION_BREAKPOINT with RIP = site+1.
var amd64Trap = [2]byte{amd64INT3, amd64NOP}

// amd64Site is one instruction that the patcher replaces.
type amd64Site struct {
	// Offset is the offset of the first instruction byte inside the page.
	// It is negative when the instruction starts in the previous page and
	// ends in this page. A SYSCALL then has Offset -1 (amd64SiteBeforePage),
	// and page[0] is its second byte. An RDFSBASE has Offset in -(Len-1)..-1.
	Offset int
	// Len is the instruction length in bytes.
	Len  int
	Kind amd64SiteKind
	// Reg is the destination register number of an RDFSBASE site, 0..15
	// (RAX=0 ... R15=15). The register is 64 bits wide when Wide is set.
	Reg uint8
	// Wide is set when the instruction has the REX.W prefix.
	Wide bool
}

// amd64Decoded is the decode result of one buffer position.
type amd64Decoded struct {
	size  uint8 // Instruction length. Zero when the bytes do not decode.
	kind  amd64SiteKind
	reg   uint8
	wide  bool
	known bool
}

// amd64Candidate is a site and the number of sweeps that decode it.
type amd64Candidate struct {
	site  amd64Site
	votes int
}

// amd64Sweep is the result of one linear decode sweep.
type amd64Sweep struct {
	// skipped counts the positions where the bytes did not decode.
	skipped int
	// sites holds the sites that the sweep decoded.
	sites []amd64Site
}

// scanAMD64 returns the sites that overlap page and that most decode sweeps
// agree on. Sites are sorted by Offset and never overlap.
//
// before holds up to 15 bytes that precede the page in guest memory, or nil
// if that memory is not mapped. after holds up to 15 bytes that follow the
// page, or nil if that memory is not mapped.
//
// A SYSCALL site is the pair 0F 05 and always has Len 2. The decoder counts
// prefixes as part of the instruction, but the debugger needs only the pair.
// A prefix in front of a patched SYSCALL stays in place and applies to INT3.
//
// A site that starts in page and ends in after is reported with its full Len.
// A site that starts in before and ends in page is reported with a negative
// Offset, so that patchAMD64 also rewrites its tail in this page. The page
// that holds the start of the site reports it with a positive Offset.
//
// The scan runs up to 16 linear sweeps with the x86asm decoder. Sweep k starts
// at byte k of before, clamped to the start of page. A sweep skips
// each byte that it cannot decode, and a sweep that skips more bytes than
// another sweep probably lost the instruction boundaries. Wrong sweeps
// resynchronize with the real instruction boundaries after a few instructions.
// A wrong sweep can stay wrong in a long run of dense vector code. A site is
// real when more than half of the sweeps with the fewest skipped bytes decode
// it as an instruction.
func scanAMD64(before, page, after []byte) []amd64Site {
	return scanAMD64GS(before, page, after, false)
}

// hasAMD64CandidateBytes reports whether buf contains the opcode bytes of a
// SYSCALL (0F 05), FSGSBASE (0F AE), or GS-prefixed instruction (65).
func hasAMD64CandidateBytes(buf []byte, gsMem bool) bool {
	for i, b := range buf {
		if b == 0x0F && i+1 < len(buf) && (buf[i+1] == 0x05 || buf[i+1] == 0xAE) {
			return true
		}
		if gsMem && b == 0x65 {
			return true
		}
	}
	return false
}

// scanAMD64GS runs scanAMD64 and, when gsMem is true, also reports memory
// instructions that carry a GS segment override prefix.
func scanAMD64GS(before, page, after []byte, gsMem bool) []amd64Site {
	if len(page) == 0 {
		return nil
	}
	buf := make([]byte, 0, len(before)+len(page)+len(after))
	buf = append(buf, before...)
	buf = append(buf, page...)
	buf = append(buf, after...)
	if !hasAMD64CandidateBytes(buf, gsMem) {
		return nil
	}
	pageStart := len(before)
	pageEnd := pageStart + len(page)

	// Each position decodes at most once, because the decode of a position
	// does not depend on the sweep that reaches it.
	decoded := make([]amd64Decoded, pageEnd)
	var runs []amd64Sweep
	fewest := -1
	prevStart := -1
	for k := 0; k < amd64SweepCount; k++ {
		start := min(k, pageStart)
		if start == prevStart {
			continue
		}
		prevStart = start
		var run amd64Sweep
		for pos := start; pos < pageEnd; {
			d := &decoded[pos]
			if !d.known {
				*d = decodeAMD64WithGS(buf[pos:], gsMem)
			}
			if d.size == 0 {
				run.skipped++
			}
			if d.kind != 0 {
				site := amd64Site{Offset: pos - pageStart, Len: int(d.size), Kind: d.kind, Reg: d.reg, Wide: d.wide}
				if d.kind == amd64SiteSyscall {
					site.Offset += int(d.size) - 2
					site.Len = 2
				}
				if site.Offset+site.Len > 0 && site.Offset < len(page) {
					run.sites = append(run.sites, site)
				}
			}
			pos += max(int(d.size), 1)
		}
		runs = append(runs, run)
		if fewest < 0 || run.skipped < fewest {
			fewest = run.skipped
		}
	}

	// A sweep that skipped more bytes than another sweep probably lost the
	// instruction boundaries. Only the sweeps with the fewest skipped bytes vote.
	candidates := make(map[int]*amd64Candidate)
	sweeps := 0
	for _, run := range runs {
		if run.skipped != fewest {
			continue
		}
		sweeps++
		for _, site := range run.sites {
			c := candidates[site.Offset]
			if c == nil {
				c = &amd64Candidate{site: site}
				candidates[site.Offset] = c
			}
			c.votes++
		}
	}

	var sites []amd64Site
	for _, c := range candidates {
		if 2*c.votes > sweeps {
			sites = append(sites, c.site)
		}
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Offset < sites[j].Offset })
	if len(sites) > 1 {
		kept := sites[:1]
		for _, s := range sites[1:] {
			prev := kept[len(kept)-1]
			if s.Offset >= prev.Offset+prev.Len {
				kept = append(kept, s)
			}
		}
		sites = kept
	}
	return sites
}

// decodeAMD64 decodes the instruction at the start of b.
func decodeAMD64(b []byte) amd64Decoded {
	return decodeAMD64WithGS(b, false)
}

func decodeAMD64WithGS(b []byte, gsMem bool) amd64Decoded {
	inst, err := decodeX86(b)
	if err != nil || inst.Len == 0 {
		return amd64Decoded{known: true}
	}
	d := amd64Decoded{size: uint8(inst.Len), known: true}
	switch inst.Op {
	case x86asm.SYSCALL:
		d.kind = amd64SiteSyscall
	case x86asm.RDFSBASE, x86asm.RDGSBASE, x86asm.WRFSBASE, x86asm.WRGSBASE:
		// Register-operand FSGSBASE instructions end with 0F AE ModRM (mod=11).
		if inst.Len < 4 || b[inst.Len-3] != 0x0F || b[inst.Len-2] != 0xAE {
			return d
		}
		modrm := b[inst.Len-1]
		if modrm>>6 != 3 {
			return d
		}
		switch modrm >> 3 & 7 {
		case 0:
			d.kind = amd64SiteRDFSBASE
		case 1:
			if !gsMem {
				return d
			}
			d.kind = amd64SiteRDGSBASE
		case 2:
			if !gsMem {
				return d
			}
			d.kind = amd64SiteWRFSBASE
		case 3:
			if !gsMem {
				return d
			}
			d.kind = amd64SiteWRGSBASE
		default:
			return d
		}
		d.reg = modrm & 7
		if inst.Len >= 4 {
			if rex := b[inst.Len-4]; rex&0xF0 == 0x40 {
				d.reg |= (rex & 1) << 3
				d.wide = rex&8 != 0
			}
		}
	default:
		if gsMem && inst.Op != x86asm.LEA && inst.Len >= 2 {
			for _, arg := range inst.Args {
				if mem, ok := arg.(x86asm.Mem); ok && mem.Segment == x86asm.GS {
					d.kind = amd64SiteGSMem
					break
				}
			}
		}
	}
	return d
}

// patchAMD64 overwrites the bytes of page for every site in sites. A SYSCALL
// site receives amd64Trap. An RDFSBASE site receives INT3 followed by NOPs for
// its whole length.
//
// A site can cross a page boundary. patchAMD64 writes only the bytes that lie
// in page. spill counts the bytes of the sites that lie beyond the end of
// page. The scan of the next page reports the same site with a negative
// Offset, and patchAMD64 on that page writes the remaining bytes.
//
// patchAMD64 returns an error if a site does not overlap page, if a SYSCALL
// site does not have Len 2, if the bytes of a SYSCALL site in page are not
// 0F 05, or if an RDFSBASE site is shorter than 4 bytes. It writes nothing
// when it returns an error.
func patchAMD64(page []byte, sites []amd64Site) (spill int, err error) {
	for _, s := range sites {
		if s.Offset >= len(page) || s.Offset+s.Len <= 0 {
			return 0, fmt.Errorf("site at %d with length %d lies outside a page of %d bytes", s.Offset, s.Len, len(page))
		}
		switch s.Kind {
		case amd64SiteSyscall, amd64SiteInt2E, amd64SiteSysenter:
			if s.Len != 2 {
				return 0, fmt.Errorf("syscall site at %d has length %d", s.Offset, s.Len)
			}
			if s.Offset < amd64SiteBeforePage {
				return 0, fmt.Errorf("syscall site at %d starts too far before the page", s.Offset)
			}
			want := [2]byte{0x0F, 0x05}
			if s.Kind == amd64SiteInt2E {
				want = [2]byte{0xCD, 0x2E}
			} else if s.Kind == amd64SiteSysenter {
				want = [2]byte{0x0F, 0x34}
			}
			for j, w := range want {
				if i := s.Offset + j; i >= 0 && i < len(page) && page[i] != w {
					return 0, fmt.Errorf("syscall site at %d: byte %d is %#x, want %#x", s.Offset, j, page[i], w)
				}
			}
		case amd64SiteRDFSBASE, amd64SiteRDGSBASE, amd64SiteWRFSBASE, amd64SiteWRGSBASE:
			if s.Len < 4 {
				return 0, fmt.Errorf("fsgsbase site at %d has length %d", s.Offset, s.Len)
			}
		case amd64SiteGSMem:
			if s.Len < 2 {
				return 0, fmt.Errorf("gs memory site at %d has length %d", s.Offset, s.Len)
			}
		case amd64SiteGuardedInsn:
			if s.Len < 2 {
				return 0, fmt.Errorf("guarded instruction site at %d has length %d", s.Offset, s.Len)
			}
		default:
			return 0, fmt.Errorf("site at %d has unknown kind %d", s.Offset, s.Kind)
		}
	}
	for _, s := range sites {
		for j := 0; j < s.Len; j++ {
			i := s.Offset + j
			if i < 0 {
				continue
			}
			if i >= len(page) {
				spill++
				continue
			}
			switch {
			case s.Kind == amd64SiteSyscall || s.Kind == amd64SiteInt2E || s.Kind == amd64SiteSysenter:
				page[i] = amd64Trap[j]
			case s.Kind == amd64SiteGuardedInsn:
				if j == 0 {
					page[i] = amd64INT3
				}
			case j == 0:
				page[i] = amd64INT3
			default:
				page[i] = amd64NOP
			}
		}
	}
	return spill, nil
}

// isX86Prefix reports whether b is a legacy instruction prefix or a REX prefix.
func isX86Prefix(b byte) bool {
	if b >= 0x40 && b <= 0x4F {
		return true
	}
	switch b {
	case 0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65:
		return true
	}
	return false
}

// amd64KernelExitKind classifies a 2-byte sequence that can transition out of
// 64-bit user mode on an x86-64 host: SYSCALL (0F 05), INT 0x2E (CD 2E), or
// SYSENTER (0F 34).
func amd64KernelExitKind(b0, b1 byte) (amd64SiteKind, bool) {
	switch {
	case b0 == 0x0F && b1 == 0x05:
		return amd64SiteSyscall, true
	case b0 == 0xCD && b1 == 0x2E:
		return amd64SiteInt2E, true
	case b0 == 0x0F && b1 == 0x34:
		return amd64SiteSysenter, true
	}
	return 0, false
}

// isRawKernelExitPair reports whether (b0, b1) forms a raw kernel-entry opcode.
func isRawKernelExitPair(b0, b1 byte) bool {
	_, ok := amd64KernelExitKind(b0, b1)
	return ok
}

// hasRawKernelExit reports whether b contains any raw kernel-entry byte pair.
func hasRawKernelExit(b []byte) bool {
	for i := 0; i+1 < len(b); i++ {
		if isRawKernelExitPair(b[i], b[i+1]) {
			return true
		}
	}
	return false
}

// hasRemainingKernelExit reports whether patchedPage, its single-byte seam with
// before or after, or after itself still contains a raw kernel-entry byte pair.
func hasRemainingKernelExit(before, patchedPage, after []byte) bool {
	if len(patchedPage) == 0 {
		return false
	}
	if len(before) > 0 && isRawKernelExitPair(before[len(before)-1], patchedPage[0]) {
		return true
	}
	if hasRawKernelExit(patchedPage) {
		return true
	}
	if len(after) > 0 && isRawKernelExitPair(patchedPage[len(patchedPage)-1], after[0]) {
		return true
	}
	return hasRawKernelExit(after)
}

// amd64HiddenExit describes a raw kernel-entry byte pair (0F 05, CD 2E, or
// 0F 34) that remains in patchedPage after primary majority-vote patching,
// together with any synchronized outer instruction in origPage that covers its
// first byte.
type amd64HiddenExit struct {
	// ExitOffset is the page-relative offset of the first byte of the 2-byte
	// kernel-entry sequence (-1 <= ExitOffset < len(origPage)).
	ExitOffset int
	// ExitKind is amd64SiteSyscall, amd64SiteInt2E, or amd64SiteSysenter.
	ExitKind amd64SiteKind
	// HasOuter reports whether synchronized decode sweeps place ExitOffset
	// inside an outer instruction [OuterOffset, OuterOffset+OuterLen) rather
	// than as a standalone exit instruction at ExitOffset.
	HasOuter    bool
	OuterOffset int
	OuterLen    int
}

// scanAMD64HiddenExits finds every raw kernel-entry byte pair overlapping
// patchedPage that still holds its raw opcode bytes, and resolves any outer
// instruction in (before, origPage, after) that covers it. When patchedPage is
// nil, origPage is used for both roles.
func scanAMD64HiddenExits(before, origPage, after, patchedPage []byte) []amd64HiddenExit {
	if len(origPage) == 0 {
		return nil
	}
	if patchedPage == nil {
		patchedPage = origPage
	}
	if !hasRemainingKernelExit(before, patchedPage, after) {
		return nil
	}

	pageStart := len(before)
	pageEnd := pageStart + len(origPage)
	origBuf := make([]byte, 0, pageEnd+len(after))
	origBuf = append(origBuf, before...)
	origBuf = append(origBuf, origPage...)
	origBuf = append(origBuf, after...)

	curByte := func(bufPos int) byte {
		if bufPos >= pageStart && bufPos < pageEnd {
			return patchedPage[bufPos-pageStart]
		}
		return origBuf[bufPos]
	}

	type rawHit struct {
		pos  int
		kind amd64SiteKind
	}
	var hits []rawHit
	loPos := max(0, pageStart-1)
	for pos := loPos; pos+1 < len(origBuf); pos++ {
		if kind, ok := amd64KernelExitKind(curByte(pos), curByte(pos+1)); ok {
			hits = append(hits, rawHit{pos: pos, kind: kind})
		}
	}
	if len(hits) == 0 {
		return nil
	}

	type step struct {
		pos int
		len uint8
	}
	type sweepSteps struct {
		skipped int
		steps   []step
	}

	insnLens := make([]int8, pageEnd)
	var runs []sweepSteps
	fewest := -1
	prevStart := -1
	for k := 0; k < amd64SweepCount; k++ {
		start := min(k, pageStart)
		if start == prevStart {
			continue
		}
		prevStart = start
		var run sweepSteps
		for pos := start; pos < pageEnd; {
			l := insnLens[pos]
			if l == 0 {
				inst, err := decodeX86(origBuf[pos:])
				if err != nil || inst.Op == 0 || inst.Len == 0 {
					l = -1
				} else {
					l = int8(inst.Len)
				}
				insnLens[pos] = l
			}
			if l < 0 {
				run.skipped++
				pos++
				continue
			}
			run.steps = append(run.steps, step{pos: pos, len: uint8(l)})
			pos += int(l)
		}
		runs = append(runs, run)
		if fewest < 0 || run.skipped < fewest {
			fewest = run.skipped
		}
	}

	isStandaloneExit := func(st step, hitPos int) bool {
		if int(st.len) < 2 || st.pos+int(st.len) != hitPos+2 {
			return false
		}
		for i := st.pos; i < hitPos; i++ {
			if !isX86Prefix(origBuf[i]) {
				return false
			}
		}
		return true
	}

	type outerKey struct {
		off int
		len int
	}
	out := make([]amd64HiddenExit, 0, len(hits))
	for _, h := range hits {
		sweeps := 0
		standaloneVotes := 0
		var outerOrder []outerKey
		outerVotes := make(map[outerKey]int, 2)
		for _, run := range runs {
			if run.skipped != fewest {
				continue
			}
			sweeps++
			// Binary search for the unique decoded step with st.pos <= h.pos.
			idx := sort.Search(len(run.steps), func(i int) bool {
				return run.steps[i].pos > h.pos
			}) - 1
			if idx < 0 {
				continue
			}
			st := run.steps[idx]
			if h.pos >= st.pos+int(st.len) {
				continue
			}
			if isStandaloneExit(st, h.pos) {
				standaloneVotes++
				continue
			}
			if st.pos < h.pos {
				key := outerKey{off: st.pos - pageStart, len: int(st.len)}
				if _, seen := outerVotes[key]; !seen {
					outerOrder = append(outerOrder, key)
				}
				outerVotes[key]++
			}
		}
		entry := amd64HiddenExit{
			ExitOffset: h.pos - pageStart,
			ExitKind:   h.kind,
		}
		if 2*standaloneVotes <= sweeps && len(outerOrder) > 0 {
			best := outerOrder[0]
			bestVotes := outerVotes[best]
			for _, k := range outerOrder[1:] {
				v := outerVotes[k]
				if v > bestVotes || (v == bestVotes && k.off > best.off) {
					best = k
					bestVotes = v
				}
			}
			entry.HasOuter = true
			entry.OuterOffset = best.off
			entry.OuterLen = best.len
		}
		touchesExit := entry.ExitOffset >= -1 && entry.ExitOffset < len(origPage)
		touchesOuter := entry.HasOuter && entry.OuterOffset < len(origPage) && entry.OuterOffset+entry.OuterLen > 0
		if touchesExit || touchesOuter {
			out = append(out, entry)
		}
	}
	return out
}

// applyAMD64HiddenExits installs single-byte INT3 traps in page for every
// hidden kernel-entry sequence in hidden (and at the start of any covering
// outer instruction whose first byte still matches origPage). It returns the
// added page-local sites sorted by Offset and any tail offsets in the preceding
// block that must also hold a trap.
func applyAMD64HiddenExits(page, origPage []byte, hidden []amd64HiddenExit) (added []amd64Site, prevTail []uint16) {
	if len(hidden) == 0 {
		return nil, nil
	}
	byOff := make(map[int]amd64Site, 2*len(hidden))
	addPrev := func(negOff int) {
		if len(page)+negOff < 0 {
			return
		}
		want := uint16(len(page) + negOff)
		for _, v := range prevTail {
			if v == want {
				return
			}
		}
		prevTail = append(prevTail, want)
	}
	for _, h := range hidden {
		if h.HasOuter {
			if h.OuterOffset < 0 {
				addPrev(h.OuterOffset)
			} else if h.OuterOffset < len(page) {
				if _, exists := byOff[h.OuterOffset]; !exists && page[h.OuterOffset] == origPage[h.OuterOffset] {
					page[h.OuterOffset] = amd64INT3
					byOff[h.OuterOffset] = amd64Site{
						Offset: h.OuterOffset,
						Len:    h.OuterLen,
						Kind:   amd64SiteGuardedInsn,
					}
				}
			}
		}
		if h.ExitOffset < 0 {
			addPrev(h.ExitOffset)
		} else if h.ExitOffset < len(page) {
			page[h.ExitOffset] = amd64INT3
			byOff[h.ExitOffset] = amd64Site{
				Offset: h.ExitOffset,
				Len:    2,
				Kind:   h.ExitKind,
			}
		}
	}
	added = make([]amd64Site, 0, len(byOff))
	for _, s := range byOff {
		added = append(added, s)
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Offset < added[j].Offset })
	return added, prevTail
}
