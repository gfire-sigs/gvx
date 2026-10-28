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

//go:build windows

package systrap

import (
	"debug/elf"
	"debug/pe"
	"fmt"
	"io"
	"runtime"
	"sync"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// Some rewrites change every word or byte run that looks like an instruction:
// the x18 rewrite on darwin and the SYSCALL scan of the amd64 Windows engine.
// A segment that holds code also holds data in the usual linker layout:
// symbol tables, relocations and read-only constants share the executable
// segment with .text. A change to a data word would corrupt the data that the
// guest reads. So these rewrites touch only the executable sections of the
// file that backs the page.

// span is a half-open range of addresses.
type span struct{ lo, hi uint64 }

// loadSegment is one PT_LOAD entry.
type loadSegment struct {
	vaddr, off, filesz uint64
}

// codeImage holds what the patcher needs from the headers of one ELF file.
type codeImage struct {
	loads []loadSegment
	// exec lists the sections that hold instructions, as file virtual addresses.
	exec []span
	// stripped is true when the file has no section headers and exec comes
	// from the executable PT_LOAD segments.
	stripped bool
}

// parseCodeImage reads the program and section headers of an ELF or PE32+ file
// of the guest architecture. It returns an error for anything else, so the
// caller leaves the page alone.
func parseCodeImage(r io.ReaderAt) (*codeImage, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		if peCI, peErr := parsePECodeImage(r); peErr == nil {
			return peCI, nil
		}
		return nil, err
	}
	want := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		want = elf.EM_AARCH64
	}
	if f.Class != elf.ELFCLASS64 || f.Machine != want {
		return nil, fmt.Errorf("the file is not a 64-bit %s ELF file (class %v, machine %v)", runtime.GOARCH, f.Class, f.Machine)
	}
	ci := &codeImage{}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			ci.loads = append(ci.loads, loadSegment{vaddr: p.Vaddr, off: p.Off, filesz: p.Filesz})
		}
	}
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Type != elf.SHT_NOBITS && s.Size > 0 {
			ci.exec = append(ci.exec, span{s.Addr, s.Addr + s.Size})
		}
	}
	if len(ci.loads) == 0 {
		return nil, fmt.Errorf("the file has no loadable segment")
	}
	if len(ci.exec) == 0 && len(f.Sections) == 0 {
		// A stripped ELF has no section headers. Fall back to PT_LOAD segments
		// with PF_X while excluding the ELF header and program header table.
		hdrEnd := uint64((64 + len(f.Progs)*56 + 3) &^ 3)
		for _, p := range f.Progs {
			if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 || p.Filesz == 0 {
				continue
			}
			lo := p.Vaddr
			hi := p.Vaddr + p.Filesz
			if p.Off < hdrEnd {
				skip := hdrEnd - p.Off
				if skip >= p.Filesz {
					continue
				}
				lo += skip
			}
			if lo < hi {
				ci.exec = append(ci.exec, span{lo: lo, hi: hi})
			}
		}
		ci.stripped = len(ci.exec) > 0
	}
	if len(ci.exec) == 0 {
		return nil, fmt.Errorf("the file has no executable section")
	}
	return ci, nil
}

// parsePECodeImage reads the section headers of a 64-bit PE32+ image for
// Wine64 guests.
func parsePECodeImage(r io.ReaderAt) (*codeImage, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	want := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	if runtime.GOARCH == "arm64" {
		want = pe.IMAGE_FILE_MACHINE_ARM64
	}
	if f.Machine != want {
		return nil, fmt.Errorf("the file is not a %s PE32+ file (machine %#x)", runtime.GOARCH, f.Machine)
	}
	if _, ok := f.OptionalHeader.(*pe.OptionalHeader64); !ok {
		return nil, fmt.Errorf("the PE file has no 64-bit optional header")
	}
	const (
		imageScnCntCode    = 0x00000020
		imageScnMemExecute = 0x20000000
	)
	ci := &codeImage{}
	for _, s := range f.Sections {
		if s.Size == 0 {
			continue
		}
		ci.loads = append(ci.loads, loadSegment{
			vaddr:  uint64(s.VirtualAddress),
			off:    uint64(s.Offset),
			filesz: uint64(s.Size),
		})
		if s.Characteristics&(imageScnCntCode|imageScnMemExecute) != 0 {
			execSize := uint64(s.VirtualSize)
			if execSize == 0 || execSize > uint64(s.Size) {
				execSize = uint64(s.Size)
			}
			ci.exec = append(ci.exec, span{
				lo: uint64(s.VirtualAddress),
				hi: uint64(s.VirtualAddress) + execSize,
			})
		}
	}
	if len(ci.loads) == 0 || len(ci.exec) == 0 {
		return nil, fmt.Errorf("the PE32+ file has no executable section")
	}
	return ci, nil
}

// bias returns the difference between a guest address and a file virtual
// address for the page at guest address base that maps file offset off.
func (ci *codeImage) bias(base, off uint64) (uint64, bool) {
	for _, l := range ci.loads {
		start := l.off &^ (subBlockSize - 1)
		end := (l.off + l.filesz + subBlockSize - 1) &^ (subBlockSize - 1)
		if off < start || off >= end {
			continue
		}
		vaddr := l.vaddr - l.off + off
		return base - vaddr, true
	}
	return 0, false
}

// codeIn returns the parts of the block at base that lie in executable
// sections. bias is the value that bias returned for the block.
func (ci *codeImage) codeIn(base, bias uint64) []span {
	return ci.codeInRange(base, blockSize, bias)
}

func (ci *codeImage) codeInRange(base, size, bias uint64) []span {
	var out []span
	for _, s := range ci.exec {
		lo, hi := s.lo+bias, s.hi+bias
		lo = max(lo, base)
		hi = min(hi, base+size)
		if lo < hi {
			out = append(out, span{lo, hi})
		}
	}
	return out
}

// imageKey identifies a file by device and inode.
type imageKey struct{ dev, ino uint64 }

// imageCache remembers the parsed headers of every file that a guest maps as
// code. A nil entry means that the file gave no usable headers.
type imageCache struct {
	mu     sync.Mutex
	images map[imageKey]*codeImage
}

// maxCachedImages bounds the cache of a platform.
const maxCachedImages = 4096

func (c *imageCache) lookup(k imageKey) (*codeImage, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ci, ok := c.images[k]
	return ci, ok
}

func (c *imageCache) store(k imageKey, ci *codeImage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.images == nil || len(c.images) >= maxCachedImages {
		c.images = make(map[imageKey]*codeImage)
	}
	c.images[k] = ci
}

// codeScope says which words of a block may hold instructions that name x18.
type codeScope struct {
	// all is true when the memory manager cannot describe mappings, so the
	// patcher treats the whole block as code.
	all bool
	// none is true for a block that holds no provable code: memory that the
	// Sentry provides, anonymous memory, and a file that is not a usable ELF
	// image.
	none bool
	// stripped is true when spans come from PF_X PT_LOAD segments without
	// section headers, so static scans require a valid instruction window.
	stripped bool
	// spans lists the code ranges when neither flag is set.
	spans []span
}

// subBlockSize is the 4KB virtual sub-block granularity inside a 16KB host page.
const subBlockSize = 4096

// subBlockMask returns a 4-bit mask of the 4KB virtual sub-blocks in the 16KB
// block at guest address base that intersect executable code spans. When the
// scope has no section boundaries (all or none), it returns 0xf so every
// sub-block follows the block-wide rule.
func (s codeScope) subBlockMask(base uint64) uint8 {
	if s.all || s.none || s.stripped {
		return 0xf
	}
	var mask uint8
	for i := uint64(0); i < blockSize/subBlockSize; i++ {
		subLo := base + i*subBlockSize
		subHi := subLo + subBlockSize
		for _, r := range s.spans {
			if max(subLo, r.lo) < min(subHi, r.hi) {
				mask |= 1 << i
				break
			}
		}
	}
	if mask == 0 {
		return 0xf
	}
	return mask
}

// contains reports whether the word at guest address a belongs to code.
func (s codeScope) contains(a uint64) bool {
	switch {
	case s.all:
		return true
	case s.none:
		return false
	}
	for _, r := range s.spans {
		if a >= r.lo && a+4 <= r.hi {
			return true
		}
	}
	return false
}

// proven reports whether the section headers of a file describe the block.
func (s codeScope) proven() bool { return !s.all && !s.none }

// containsRange reports whether the n bytes at guest address a all belong to
// code.
func (s codeScope) containsRange(a, n uint64) bool {
	switch {
	case s.all:
		return true
	case s.none:
		return false
	}
	for _, r := range s.spans {
		if a >= r.lo && a+n <= r.hi {
			return true
		}
	}
	return false
}

// scopeOf decides which words of the block at base the x18 rewrite may touch.
//
// WHY: the rewrite recognises instructions by their bit pattern, so it also
// changes a data word that decodes as an instruction naming x18. Only words
// that provably hold code are safe. A file image proves it with the section
// headers. Anonymous memory has no headers, and the code that a JIT engine
// writes there shares pages with constants and tables. A rewrite of such a
// page changed V8 object pointers and killed one run in six with SIGSEGV. JIT
// engines reserve x18 as the platform register, as the arm64 ABI allows, so
// leaving anonymous code alone loses no guest that exists. A guest that keeps
// a value in x18 across an interrupt in anonymous code still runs, but the
// kernel of macOS can zero the value.
func (p *Platform) scopeOf(ctx context.Context, m interface{}, base uint64) codeScope {
	im, ok := m.(platform.ExecImageProvider)
	if !ok {
		return codeScope{all: true}
	}
	var spans []span
	stripped := false
	for s := uint64(0); s < blockSize/subBlockSize; s++ {
		subBase := base + s*subBlockSize
		info := im.ExecImageAt(ctx, hostarch.Addr(subBase))
		if info.Kind != platform.MappingFile {
			continue
		}
		key := imageKey{info.Device, info.Inode}
		ci, cached := p.images.lookup(key)
		if !cached {
			parsed, err := parseCodeImage(info.File)
			if err != nil {
				parsed = nil
			}
			ci = parsed
			p.images.store(key, ci)
		}
		info.Release()
		if ci == nil {
			continue
		}
		bias, ok := ci.bias(subBase, info.Offset)
		if !ok {
			continue
		}
		if ci.stripped {
			stripped = true
		}
		for _, sp := range ci.codeInRange(subBase, subBlockSize, bias) {
			if n := len(spans); n > 0 && spans[n-1].hi == sp.lo {
				spans[n-1].hi = sp.hi
			} else {
				spans = append(spans, sp)
			}
		}
	}
	if len(spans) == 0 {
		return codeScope{none: true}
	}
	return codeScope{stripped: stripped, spans: spans}
}
