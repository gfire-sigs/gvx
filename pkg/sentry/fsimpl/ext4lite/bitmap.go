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

package ext4lite

import "math/bits"

// bitmapWords is the number of 64-bit words of a group bitmap. Both the
// block bitmap and the inode bitmap of a group hold 4,096 bits.
const bitmapWords = blocksPerGroup / 64

// bitmap is the allocation bitmap of one group. Bit i lives in word i/64, so
// the little-endian serialization matches the byte layout of ext4.
type bitmap [bitmapWords]uint64

func (b *bitmap) test(i uint32) bool { return b[i>>6]>>(i&63)&1 != 0 }
func (b *bitmap) set(i uint32)       { b[i>>6] |= 1 << (i & 63) }
func (b *bitmap) clear(i uint32)     { b[i>>6] &^= 1 << (i & 63) }

// count returns the number of set bits.
func (b *bitmap) count() uint32 {
	var n int
	for _, w := range b {
		n += bits.OnesCount64(w)
	}
	return uint32(n)
}

// firstFree returns the first index i >= from where neither b nor mask has the
// bit set. mask can be nil. It returns blocksPerGroup when no index is free.
func (b *bitmap) firstFree(from uint32, mask *bitmap) uint32 {
	for w := from >> 6; w < bitmapWords; w++ {
		used := b[w]
		if mask != nil {
			used |= mask[w]
		}
		if w == from>>6 {
			used |= 1<<(from&63) - 1
		}
		if used != ^uint64(0) {
			return w<<6 + uint32(bits.TrailingZeros64(^used))
		}
	}
	return blocksPerGroup
}

// freeRun returns the length of the run of free bits that starts at i, capped
// at limit. A bit is free when neither b nor mask has it set.
func (b *bitmap) freeRun(i, limit uint32, mask *bitmap) uint32 {
	n := uint32(0)
	for n < limit && i+n < blocksPerGroup {
		w := (i + n) >> 6
		used := b[w]
		if mask != nil {
			used |= mask[w]
		}
		used >>= (i + n) & 63
		if used == 0 {
			step := 64 - (i+n)&63
			n += min(step, limit-n)
			continue
		}
		n += min(uint32(bits.TrailingZeros64(used)), limit-n)
		break
	}
	return n
}

// encode writes the bitmap into dst, which must hold 512 bytes.
func (b *bitmap) encode(dst []byte) {
	for i, w := range b {
		le.PutUint64(dst[i*8:], w)
	}
}

// decode reads the bitmap from src, which must hold 512 bytes.
func (b *bitmap) decode(src []byte) {
	for i := range b {
		b[i] = le.Uint64(src[i*8:])
	}
}

// andNot clears in b every bit that is set in o.
func (b *bitmap) andNot(o *bitmap) {
	for i := range b {
		b[i] &^= o[i]
	}
}
