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

//go:build darwin && arm64

package systrap

import (
	"encoding/binary"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// storeToExecBlock handles a write fault into a block that the guest maps
// writable and executable, or into a writable 4KB sub-block of a composite
// 16KB host block. The site is the stub address of the storing instruction,
// and farGuest is the guest address of the target. It returns false when the
// fault has another cause.
func (c *Context) storeToExecBlock(as *addressSpace, sm *sysmsg, site, farGuest uint64) (signalAction, bool) {
	stubFar := as.p.stubAddr(farGuest)
	base := blockRound(stubFar)
	subWrite, canRestore := as.subBlockWriteInfo(stubFar)
	if !subWrite {
		return signalAction{}, false
	}
	if canRestore && blockRound(site) != base {
		ok, err := as.restoreData(base)
		if err != nil {
			return contextErr(err, unix.ENOMEM), true
		}
		if ok {
			return signalAction{resume: true}, true
		}
		if st, at, found := as.blockStateOf(base); found && st == blockData && at.Write {
			return signalAction{resume: true}, true
		}
		return signalAction{}, false
	}
	if as.emulateSubBlockStore(sm, site) {
		return signalAction{resume: true}, true
	}
	as.logSelfStore(site, farGuest)
	return signalAction{}, false
}

// subBlockWriteInfo reports whether the 4KB sub-block at stubAddr is mapped
// with guest write permission, and whether the containing 16KB host block can
// be restored to direct hardware read-write access.
func (as *addressSpace) subBlockWriteInfo(stubAddr uint64) (writable, canRestore bool) {
	base := blockRound(stubAddr)
	subIdx := (stubAddr - base) / subBlockSize
	as.mu.Lock()
	defer as.mu.Unlock()
	hb := as.hostBlocks[base]
	if hb == nil {
		blk := as.blocks[base]
		if blk != nil && blk.at.Write {
			return true, true
		}
		return false, false
	}
	sub := hb.subs[subIdx]
	if sub.src == 0 || !sub.at.Write {
		return false, false
	}
	blk := as.blocks[base]
	canRestore = blk != nil && blk.state == blockExec && hb.canMapDirect() && hb.writeMask == 0xF
	return true, canRestore
}

// emulateSharedPageStore is an alias for emulateSubBlockStore.
func (as *addressSpace) emulateSharedPageStore(sm *sysmsg, site uint64) bool {
	return as.emulateSubBlockStore(sm, site)
}

// emulateSubBlockStore runs the store, LSE atomic, or DC ZVA instruction at
// stub address site when the target lies in a writable 4KB sub-block whose
// 16KB host block is mapped read-only or read-execute.
func (as *addressSpace) emulateSubBlockStore(sm *sysmsg, site uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return false
	}
	insn, ok := as.codeWordLocked(site)
	if !ok {
		return false
	}
	check := func(addr uint64, n int) bool {
		if n <= 0 {
			return false
		}
		stubStart := as.p.stubAddr(addr)
		stubEnd := stubStart + uint64(n)
		for cur := stubStart &^ 3; cur < stubEnd; cur += 4 {
			tBase := blockRound(cur)
			ts := int((cur - tBase) / subBlockSize)
			tHB := as.hostBlocks[tBase]
			tBlk := as.blocks[tBase]
			if tHB != nil {
				sub := tHB.subs[ts]
				if sub.src == 0 || !sub.at.Write {
					return false
				}
				if tBlk != nil && tBlk.state == blockExec && tBlk.priv != 0 && tHB.execMask&(1<<ts) != 0 {
					subOff := cur - (tBase + uint64(ts)*subBlockSize)
					srcPage := unsafe.Slice((*byte)(addrPtr(sub.src)), subBlockSize)
					privPage := pageBytes(tBlk.priv)
					if binary.LittleEndian.Uint32(srcPage[subOff:]) != binary.LittleEndian.Uint32(privPage[cur-tBase:]) {
						return false
					}
				}
				continue
			}
			if tBlk == nil || tBlk.state != blockExec || tBlk.priv == 0 || !tBlk.at.Write {
				return false
			}
			srcPage := pageBytes(tBlk.src)
			privPage := pageBytes(tBlk.priv)
			w := cur - tBase
			if binary.LittleEndian.Uint32(srcPage[w:]) != binary.LittleEndian.Uint32(privPage[w:]) {
				return false
			}
		}
		return true
	}
	read := func(addr uint64, n int) []byte {
		out := make([]byte, n)
		stubStart := as.p.stubAddr(addr)
		for i := 0; i < n; i++ {
			cur := stubStart + uint64(i)
			tBase := blockRound(cur)
			ts := int((cur - tBase) / subBlockSize)
			if tHB := as.hostBlocks[tBase]; tHB != nil {
				sub := tHB.subs[ts]
				subOff := cur - (tBase + uint64(ts)*subBlockSize)
				srcSlice := unsafe.Slice((*byte)(addrPtr(sub.src)), subBlockSize)
				out[i] = srcSlice[subOff]
			} else if tBlk := as.blocks[tBase]; tBlk != nil && tBlk.src != 0 {
				out[i] = pageBytes(tBlk.src)[cur-tBase]
			}
		}
		return out
	}
	write := func(addr uint64, b []byte) {
		stubStart := as.p.stubAddr(addr)
		tBase := blockRound(stubStart)
		ts := int((stubStart - tBase) / subBlockSize)
		subOff := stubStart - (tBase + uint64(ts)*subBlockSize)
		if tHB := as.hostBlocks[tBase]; tHB != nil && subOff+uint64(len(b)) <= subBlockSize {
			sub := tHB.subs[ts]
			switch {
			case len(b) == 4 && stubStart&3 == 0:
				v32 := binary.LittleEndian.Uint32(b)
				atomic.StoreUint32((*uint32)(unsafe.Add(addrPtr(sub.src), subOff)), v32)
				for _, cHB := range as.compBlocks {
					if cHB.comp == 0 {
						continue
					}
					for cs := 0; cs < subBlocksPerBlock; cs++ {
						if cHB.subs[cs].src == sub.src {
							atomic.StoreUint32((*uint32)(unsafe.Add(addrPtr(cHB.comp), uint64(cs)*subBlockSize+subOff)), v32)
						}
					}
				}
				if tBlk := as.blocks[tBase]; tBlk != nil && tBlk.priv != 0 {
					atomic.StoreUint32((*uint32)(unsafe.Add(addrPtr(tBlk.priv), stubStart-tBase)), v32)
				}
				return
			case len(b) == 8 && stubStart&7 == 0:
				v64 := binary.LittleEndian.Uint64(b)
				atomic.StoreUint64((*uint64)(unsafe.Add(addrPtr(sub.src), subOff)), v64)
				for _, cHB := range as.compBlocks {
					if cHB.comp == 0 {
						continue
					}
					for cs := 0; cs < subBlocksPerBlock; cs++ {
						if cHB.subs[cs].src == sub.src {
							atomic.StoreUint64((*uint64)(unsafe.Add(addrPtr(cHB.comp), uint64(cs)*subBlockSize+subOff)), v64)
						}
					}
				}
				if tBlk := as.blocks[tBase]; tBlk != nil && tBlk.priv != 0 {
					atomic.StoreUint64((*uint64)(unsafe.Add(addrPtr(tBlk.priv), stubStart-tBase)), v64)
				}
				return
			}
		}
		for i, v := range b {
			cur := stubStart + uint64(i)
			tBase := blockRound(cur)
			ts := int((cur - tBase) / subBlockSize)
			if tHB := as.hostBlocks[tBase]; tHB != nil {
				sub := tHB.subs[ts]
				subOff := cur - (tBase + uint64(ts)*subBlockSize)
				unsafe.Slice((*byte)(addrPtr(sub.src)), subBlockSize)[subOff] = v
				for _, cHB := range as.compBlocks {
					if cHB.comp == 0 {
						continue
					}
					for cs := 0; cs < subBlocksPerBlock; cs++ {
						if cHB.subs[cs].src == sub.src {
							pageBytes(cHB.comp)[uint64(cs)*subBlockSize+subOff] = v
						}
					}
				}
			} else if tBlk := as.blocks[tBase]; tBlk != nil && tBlk.src != 0 {
				pageBytes(tBlk.src)[cur-tBase] = v
			}
			if tBlk := as.blocks[tBase]; tBlk != nil && tBlk.priv != 0 {
				pageBytes(tBlk.priv)[cur-tBase] = v
			}
		}
	}
	regs := storeRegs{ss: &sm.MC.SS, ns: &sm.MC.NS, x18: &sm.X18}
	if st, ok := decodeStore(insn); ok {
		if st.exclusive {
			if done, ok := as.emulateExclusiveStoreLocked(site, st, regs, check, read, write); done {
				if ok {
					sm.MC.SS.PC = site + 4
				}
				return ok
			}
		}
		if _, ok := st.execute(regs, check, write); !ok {
			return false
		}
		sm.MC.SS.PC = site + 4
		return true
	}
	if _, ok := emulateAtomicOrCacheOp(insn, regs, check, read, write); ok {
		sm.MC.SS.PC = site + 4
		return true
	}
	return false
}

// emulateExclusiveStoreLocked verifies or re-evaluates the preceding
// load-exclusive sequence under as.mu so concurrent LL/SC loops on a composite
// 16KB host block cannot lose updates or succeed with stale values.
func (as *addressSpace) emulateExclusiveStoreLocked(
	site uint64,
	st storeInsn,
	regs storeRegs,
	check func(addr uint64, n int) bool,
	read func(addr uint64, n int) []byte,
	write func(addr uint64, b []byte),
) (done, ok bool) {
	addr, _, _ := st.address(regs)
	total := st.size
	if st.pair {
		total *= 2
	}
	if !check(addr, total) {
		return true, false
	}
	for k := 1; k <= 16; k++ {
		if site < uint64(k*4) {
			break
		}
		ldInsn, ok := as.codeWordLocked(site - uint64(k*4))
		if !ok {
			break
		}
		if ldInsn&0x3f400000 != 0x08400000 {
			continue
		}
		o2 := (ldInsn >> 23) & 1
		o1 := (ldInsn >> 21) & 1
		ldSingle := o2 == 0 && o1 == 0
		ldPair := o2 == 0 && o1 == 1 && (ldInsn>>30) >= 2
		if (st.pair && !ldPair) || (!st.pair && !ldSingle) {
			continue
		}
		ldSize := 1 << (ldInsn >> 30)
		ldBase := uint8((ldInsn >> 5) & 31)
		if ldSize != st.size || ldBase != st.base {
			continue
		}
		rtOld := uint8(ldInsn & 31)
		rtOld2 := uint8((ldInsn >> 10) & 31)
		mask := maskBySize(st.size)
		curVal := decodeLEUint(read(addr, st.size)) & mask
		if !st.pair {
			if k == 1 && rtOld != st.base && rtOld != st.rt {
				write(addr, st.value(regs, st.rt))
				regs.ss.setReg(rtOld, curVal, regs.x18, false)
				if st.status != 31 {
					regs.set(st.status, 0)
				}
				return true, true
			}
			if k >= 2 && rtOld == st.rt && rtOld != st.base {
				if k >= 3 {
					if mid, ok := as.codeWordLocked(site - uint64((k-1)*4)); ok {
						switch {
						case mid&0x7f000000 == 0x35000000 && uint8(mid&31) == rtOld: // CBNZ rtOld, label
							if curVal != 0 {
								if st.status != 31 {
									regs.set(st.status, 1)
								}
								return true, true
							}
						case mid&0x7f000000 == 0x34000000 && uint8(mid&31) == rtOld: // CBZ rtOld, label
							if curVal == 0 {
								if st.status != 31 {
									regs.set(st.status, 1)
								}
								return true, true
							}
						case mid&0x7f80001f == 0x7100001f && uint8((mid>>5)&31) == rtOld: // CMP rtOld, #imm
							imm := uint64((mid >> 10) & 0xfff)
							if (mid>>22)&1 == 1 {
								imm <<= 12
							}
							if curVal != (imm & mask) {
								if st.status != 31 {
									regs.set(st.status, 1)
								}
								return true, true
							}
							write(addr, st.value(regs, st.rt))
							if st.status != 31 {
								regs.set(st.status, 0)
							}
							return true, true
						case mid&0x7f20001f == 0x6b00001f && uint8((mid>>5)&31) == rtOld: // CMP rtOld, rm
							rm := uint8((mid >> 16) & 31)
							if rm != rtOld {
								if curVal != (regs.get(rm, false) & mask) {
									if st.status != 31 {
										regs.set(st.status, 1)
									}
									return true, true
								}
								write(addr, st.value(regs, st.rt))
								if st.status != 31 {
									regs.set(st.status, 0)
								}
								return true, true
							}
						}
					}
				}
				if aluInsn, ok := as.codeWordLocked(site - 4); ok {
					if newVal, ok := evalExclusiveALU(aluInsn, rtOld, curVal, regs); ok {
						newVal &= mask
						write(addr, encodeLEUint(newVal, st.size))
						regs.ss.setReg(rtOld, newVal, regs.x18, false)
						if st.status != 31 {
							regs.set(st.status, 0)
						}
						return true, true
					}
				}
				write(addr, st.value(regs, st.rt))
				if st.status != 31 {
					regs.set(st.status, 0)
				}
				return true, true
			}
			if rtOld != st.rt {
				if curVal != (regs.get(rtOld, false) & mask) {
					if st.status != 31 {
						regs.set(st.status, 1)
					}
					return true, true
				}
				write(addr, st.value(regs, st.rt))
				if st.status != 31 {
					regs.set(st.status, 0)
				}
				return true, true
			}
			return false, false
		}
		if rtOld != st.rt && rtOld != st.rt2 && rtOld2 != st.rt && rtOld2 != st.rt2 {
			curVal2 := decodeLEUint(read(addr+uint64(st.size), st.size)) & mask
			if k == 1 && rtOld != st.base && rtOld2 != st.base {
				write(addr, st.value(regs, st.rt))
				write(addr+uint64(st.size), st.value(regs, st.rt2))
				regs.ss.setReg(rtOld, curVal, regs.x18, false)
				regs.ss.setReg(rtOld2, curVal2, regs.x18, false)
				if st.status != 31 {
					regs.set(st.status, 0)
				}
				return true, true
			}
			if curVal != (regs.get(rtOld, false)&mask) || curVal2 != (regs.get(rtOld2, false)&mask) {
				if st.status != 31 {
					regs.set(st.status, 1)
				}
				return true, true
			}
			write(addr, st.value(regs, st.rt))
			write(addr+uint64(st.size), st.value(regs, st.rt2))
			if st.status != 31 {
				regs.set(st.status, 0)
			}
			return true, true
		}
		return false, false
	}
	return false, false
}
