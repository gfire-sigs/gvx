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

//go:build (darwin && arm64) || windows

package systrap

import (
	"debug/elf"
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
}

// parseCodeImage reads the program and section headers of an ELF file of the
// guest architecture. It returns an error for anything else, so the caller
// leaves the page alone.
func parseCodeImage(r io.ReaderAt) (*codeImage, error) {
	f, err := elf.NewFile(r)
	if err != nil {
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
	if len(ci.exec) == 0 {
		// A file without section headers gives no way to separate code from data.
		return nil, fmt.Errorf("the file has no executable section")
	}
	return ci, nil
}

// bias returns the difference between a guest address and a file virtual
// address for the page at guest address base that maps file offset off.
func (ci *codeImage) bias(base, off uint64) (uint64, bool) {
	for _, l := range ci.loads {
		start := l.off &^ (blockSize - 1)
		end := (l.off + l.filesz + blockSize - 1) &^ (blockSize - 1)
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
	var out []span
	for _, s := range ci.exec {
		lo, hi := s.lo+bias, s.hi+bias
		lo = max(lo, base)
		hi = min(hi, base+blockSize)
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
	// spans lists the code ranges when neither flag is set.
	spans []span
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
	info := im.ExecImageAt(ctx, hostarch.Addr(base))
	if info.Kind != platform.MappingFile {
		return codeScope{none: true}
	}
	defer info.Release()
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
	if ci == nil {
		return codeScope{none: true}
	}
	bias, ok := ci.bias(base, info.Offset)
	if !ok {
		return codeScope{none: true}
	}
	return codeScope{spans: ci.codeIn(base, bias)}
}
