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
	"fmt"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// subprocessBlockHost runs the stub side of the sub-block layer through the
// syscall thread of a subprocess.
type subprocessBlockHost struct {
	s *subprocess
}

// mapRange implements blockHost.mapRange.
func (h subprocessBlockHost) mapRange(addr, length uintptr, prot int, populate bool, fd int, off uint64) error {
	flags := unix.MAP_SHARED | unix.MAP_FIXED
	if populate {
		flags |= unix.MAP_POPULATE
	}
	_, err := h.s.syscall(
		unix.SYS_MMAP,
		arch.SyscallArgument{Value: addr},
		arch.SyscallArgument{Value: length},
		arch.SyscallArgument{Value: uintptr(prot)},
		arch.SyscallArgument{Value: uintptr(flags)},
		arch.SyscallArgument{Value: uintptr(fd)},
		arch.SyscallArgument{Value: uintptr(off)})
	return err
}

// unmapRange implements blockHost.unmapRange.
func (h subprocessBlockHost) unmapRange(addr, length uintptr) error {
	_, err := h.s.syscall(
		unix.SYS_MUNMAP,
		arch.SyscallArgument{Value: addr},
		arch.SyscallArgument{Value: length})
	return err
}

// allocComp implements blockHost.allocComp.
func (h subprocessBlockHost) allocComp() (compPage, error) {
	mf := h.s.memoryFile
	fr, err := mf.Allocate(subBlockSize, pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		return compPage{}, err
	}
	if fr.Start%uint64(hostPageSize) != 0 {
		mf.DecRef(fr)
		return compPage{}, fmt.Errorf("the memory file range %v is not aligned to the host page", fr)
	}
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		mf.DecRef(fr)
		return compPage{}, err
	}
	if bs.NumBlocks() != 1 || bs.Head().Len() != subBlockSize {
		mf.DecRef(fr)
		return compPage{}, fmt.Errorf("the memory file range %v has %d mappings", fr, bs.NumBlocks())
	}
	return compPage{fr: fr, buf: bs.Head().ToSlice()}, nil
}

// freeComp implements blockHost.freeComp.
func (h subprocessBlockHost) freeComp(c compPage) {
	h.s.memoryFile.DecRef(c.fr)
}

// compFD implements blockHost.compFD.
func (h subprocessBlockHost) compFD() int {
	return h.s.memoryFile.FD()
}

// initSubBlocks creates the sub-block layer of a subprocess, or removes it
// when the host does not need it. A subprocess has no guest mapping when it
// calls this function.
func (s *subprocess) initSubBlocks() {
	switch {
	case !subBlocksEnabled():
		s.subBlocks = nil
	case s.subBlocks == nil:
		s.subBlocks = newSubBlockLayer(subprocessBlockHost{s})
	}
}

var _ platform.HostBlockOwner = (*subprocess)(nil)

// AdoptHostBlock implements platform.HostBlockOwner.AdoptHostBlock.
func (s *subprocess) AdoptHostBlock(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, spare uint8) {
	if s.subBlocks == nil {
		ownedBlock{f: f, fr: fr, spare: spare}.release()
		return
	}
	s.subBlocks.adopt(uintptr(addr), f, fr, spare)
}

// ReleaseHostBlocks implements platform.HostBlockOwner.ReleaseHostBlocks.
func (s *subprocess) ReleaseHostBlocks(ar hostarch.AddrRange) {
	if s.subBlocks != nil {
		s.subBlocks.release(ar)
	}
}

// resetSubBlocks forgets the blocks of a subprocess after the stub unmapped
// its guest memory.
func (s *subprocess) resetSubBlocks() {
	if s.subBlocks != nil {
		s.subBlocks.reset()
	}
}

// HostBlockSize implements platform.HostBlockPlatform.HostBlockSize.
func (*Systrap) HostBlockSize() uint64 {
	if subBlocksEnabled() {
		return subBlockSize
	}
	return 0
}
