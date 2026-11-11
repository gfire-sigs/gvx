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

//go:build linux && amd64

package usertrap

import (
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
)

// siteWrite describes one step of a syscall patch or unpatch within the
// jmpInstLen bytes of a patch site.
type siteWrite struct {
	off  int
	data []byte
}

// rewriteSite writes each step in order to the frames that back addr.
// WithPinnedMappings blocks concurrent unmap or remap calls until all steps
// finish. That lock prevents split writes across old and new frames. When old
// is non-nil, rewriteSite compares the bytes at addr with *old first. On
// mismatch, it returns false without modifying memory.
func rewriteSite(ctx context.Context, mm memoryManager, addr hostarch.Addr, old *[jmpInstLen]uint8, writes ...siteWrite) (bool, error) {
	matched := true
	err := mm.WithPinnedMappings(ctx, addr, jmpInstLen, func(ims safemem.BlockSeq) error {
		if old != nil {
			var current [jmpInstLen]uint8
			if _, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(current[:])), ims); err != nil {
				return err
			}
			if current != *old {
				matched = false
				return nil
			}
		}
		for _, w := range writes {
			if _, err := safemem.CopySeq(ims.DropFirst(w.off), safemem.BlockSeqOf(safemem.BlockFromSafeSlice(w.data))); err != nil {
				return err
			}
		}
		return nil
	})
	return matched, err
}

// patchSyscallSite writes newCode over a verified syscall sequence at patchAddr
// in one pinned pass. It writes 0x06 at faultInstOffset, then bytes 1..6, and
// last byte 0.
func patchSyscallSite(ctx context.Context, mm memoryManager, patchAddr uintptr, sysno uintptr, newCode [jmpInstLen]uint8) (bool, error) {
	prev := origSyscallCode(uint32(sysno))
	applied, err := rewriteSite(ctx, mm, hostarch.Addr(patchAddr), &prev,
		siteWrite{off: int(faultInstOffset), data: faultInst[:]},
		siteWrite{off: 1, data: newCode[1:]},
		siteWrite{off: 0, data: newCode[0:1]})
	if err == nil && !applied {
		ctx.Debugf("The code at %x changed before the patch, skip it", patchAddr)
	}
	return applied, err
}

// unpatchSyscallSite restores origCode at patchAddr in one pinned pass. It
// writes 0x06 at offset 0, then bytes 1..6, and last byte 0.
func unpatchSyscallSite(ctx context.Context, mm memoryManager, patchAddr hostarch.Addr, sysno uint32, origCode [jmpInstLen]uint8) error {
	if _, err := rewriteSite(ctx, mm, patchAddr, nil,
		siteWrite{off: 0, data: faultInst[:]},
		siteWrite{off: 1, data: origCode[1:]},
		siteWrite{off: 0, data: origCode[0:1]}); err != nil {
		ctx.Warningf("Failed to unpatch syscall at %x (sysno %d): %v", patchAddr, sysno, err)
		return err
	}
	return nil
}
