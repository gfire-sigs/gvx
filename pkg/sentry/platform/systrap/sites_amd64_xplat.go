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

//go:build (darwin || windows) && amd64

package systrap

// siteInfo describes one patched instruction.
type siteInfo struct {
	kind    amd64SiteKind
	reg     uint8
	scratch uint8
	wide    bool
	store   bool
	length  uint8
	disp    int32
	// tail is the address of the slot tail of a winSiteJump.
	tail uint64
	// entry is the address in a pre-window slot where a thread continues when
	// it starts at this site. It is the first instruction of the slot for a
	// winSiteRelocated, and the entry code of the slot for the SYSCALL of a
	// pre-window. Zero means that the site has no entry.
	entry uint64
}

const (
	// winSiteJump marks the SYSCALL that became a JMP to a slot. The debugger
	// never sees a trap there, so the kind only serves resumePC.
	winSiteJump amd64SiteKind = 0x80 + iota
	// winSiteJumpBefore marks the JMP that replaced the instructions in front of
	// a SYSCALL. The SYSCALL itself keeps its trap and its amd64SiteSyscall site.
	winSiteJumpBefore
	// winSiteRelocated marks the start of a relocated instruction of a
	// pre-window, other than the first. A thread that starts there continues
	// at the same instruction in the slot, because the JMP overwrote the bytes.
	winSiteRelocated
)

// preWindowSites returns the sites of a pre-window patch, by page offset. The
// JMP starts at page offset start and enters the slot at slotVA. insn holds the
// offset of each relocated instruction, counted from start, and s is the
// SYSCALL, which keeps its trap.
//
// A thread that the Sentry starts at the SYSCALL enters the slot behind the
// relocated instructions, because they have run. A thread that starts at
// another relocated instruction continues at that instruction in the slot,
// because the JMP overwrote the bytes of the original code.
func preWindowSites(start int, slotVA uint64, insn []uint8, s amd64Site) map[uint16]siteInfo {
	sites := make(map[uint16]siteInfo, len(insn)+1)
	sites[uint16(start)] = siteInfo{kind: winSiteJumpBefore}
	for _, off := range insn[1:] {
		sites[uint16(start+int(off))] = siteInfo{kind: winSiteRelocated, entry: slotVA + uint64(off)}
	}
	sites[uint16(s.Offset)] = siteInfo{kind: s.Kind, reg: s.Reg, wide: s.Wide, length: uint8(s.Len), entry: slotVA + uint64(s.Offset-start)}
	return sites
}
