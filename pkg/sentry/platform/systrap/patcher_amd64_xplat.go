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
)

const (
	// amd64PageSize is the page size of the Windows engine.
	amd64PageSize = 4096

	// amd64MaxInsnLen is the longest amd64 instruction in bytes. It sets the
	// context that the scan needs on each side of a page.
	amd64MaxInsnLen = 15

	// amd64SweepCount is the number of linear decode sweeps of one scan.
	amd64SweepCount = amd64MaxInsnLen + 1

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
// at 15-k bytes before the page, clamped to the start of before. A sweep that
// cannot decode a byte skips it. Wrong sweeps resynchronize with the real
// instruction boundaries after a few instructions. A site is real when more
// than half of the distinct sweeps decode it as an instruction.
func scanAMD64(before, page, after []byte) []amd64Site {
	if len(page) == 0 {
		return nil
	}
	buf := make([]byte, 0, len(before)+len(page)+len(after))
	buf = append(buf, before...)
	buf = append(buf, page...)
	buf = append(buf, after...)
	pageStart := len(before)
	pageEnd := pageStart + len(page)

	// Each position decodes at most once, because the decode of a position
	// does not depend on the sweep that reaches it.
	decoded := make([]amd64Decoded, pageEnd)
	candidates := make(map[int]*amd64Candidate)
	sweeps := 0
	prevStart := -1
	for k := 0; k < amd64SweepCount; k++ {
		start := max(pageStart-amd64MaxInsnLen+k, 0)
		if start == prevStart {
			continue
		}
		prevStart = start
		sweeps++
		for pos := start; pos < pageEnd; {
			d := &decoded[pos]
			if !d.known {
				*d = decodeAMD64(buf[pos:])
			}
			if d.kind != 0 {
				site := amd64Site{Offset: pos - pageStart, Len: int(d.size), Kind: d.kind, Reg: d.reg, Wide: d.wide}
				if d.kind == amd64SiteSyscall {
					site.Offset += int(d.size) - 2
					site.Len = 2
				}
				if site.Offset+site.Len > 0 && site.Offset < len(page) {
					c := candidates[site.Offset]
					if c == nil {
						c = &amd64Candidate{site: site}
						candidates[site.Offset] = c
					}
					c.votes++
				}
			}
			pos += max(int(d.size), 1)
		}
	}

	var sites []amd64Site
	for _, c := range candidates {
		if 2*c.votes > sweeps {
			sites = append(sites, c.site)
		}
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Offset < sites[j].Offset })
	return sites
}

// decodeAMD64 decodes the instruction at the start of b.
func decodeAMD64(b []byte) amd64Decoded {
	inst, err := x86asm.Decode(b, 64)
	if err != nil || inst.Len == 0 {
		return amd64Decoded{known: true}
	}
	d := amd64Decoded{size: uint8(inst.Len), known: true}
	switch inst.Op {
	case x86asm.SYSCALL:
		d.kind = amd64SiteSyscall
	case x86asm.RDFSBASE:
		// The last byte is ModRM. A REX prefix, when present, sits directly
		// before the two opcode bytes 0F AE.
		modrm := b[inst.Len-1]
		if modrm>>6 != 3 || modrm>>3&7 != 0 {
			return d
		}
		d.kind = amd64SiteRDFSBASE
		d.reg = modrm & 7
		if inst.Len >= 4 {
			if rex := b[inst.Len-4]; rex&0xF0 == 0x40 {
				d.reg |= (rex & 1) << 3
				d.wide = rex&8 != 0
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
		case amd64SiteSyscall:
			if s.Len != 2 {
				return 0, fmt.Errorf("syscall site at %d has length %d", s.Offset, s.Len)
			}
			if s.Offset < amd64SiteBeforePage {
				return 0, fmt.Errorf("syscall site at %d starts too far before the page", s.Offset)
			}
			want := [2]byte{0x0F, 0x05}
			for j, w := range want {
				if i := s.Offset + j; i >= 0 && i < len(page) && page[i] != w {
					return 0, fmt.Errorf("syscall site at %d: byte %d is %#x, want %#x", s.Offset, j, page[i], w)
				}
			}
		case amd64SiteRDFSBASE:
			if s.Len < 4 {
				return 0, fmt.Errorf("rdfsbase site at %d has length %d", s.Offset, s.Len)
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
			case s.Kind == amd64SiteSyscall:
				page[i] = amd64Trap[j]
			case j == 0:
				page[i] = amd64INT3
			default:
				page[i] = amd64NOP
			}
		}
	}
	return spill, nil
}
