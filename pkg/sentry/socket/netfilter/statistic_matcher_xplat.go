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

package netfilter

import (
	"fmt"
	"math/rand/v2"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/bits"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the xt_statistic match (iptables "-m statistic").
// Ref: include/uapi/linux/netfilter/xt_statistic.h and net/netfilter/xt_statistic.c.
// Kubernetes kube-proxy uses "--mode random --probability P" in iptables
// mode to spread connections across the endpoints of a service.

const (
	matcherNameStatistic = "statistic"

	// statisticRevision0 is the only revision of struct xt_statistic_info.
	statisticRevision0 uint8 = 0

	statisticModeRandom uint16 = 0
	statisticModeNth    uint16 = 1

	// statisticFlagInvert is XT_STATISTIC_INVERT. Linux rejects every other bit.
	statisticFlagInvert uint16 = 1

	// statisticInfoSize is sizeof(struct xt_statistic_info) on a 64-bit
	// kernel: mode, flags, 12 bytes of union, 4 bytes of padding, and the
	// 8-byte private master pointer.
	statisticInfoSize = 24

	// statisticRandomMask keeps 31 bits of a random number. Userspace counts
	// the probability in units of 2^-31.
	statisticRandomMask uint32 = 0x7FFFFFFF
)

// Byte offsets of the fields of struct xt_statistic_info.
const (
	statisticOffMode  = 0
	statisticOffFlags = 2
	// statisticOffUnion is the start of the 12-byte union.
	statisticOffUnion = 4
	statisticUnionLen = 3
)

// Indexes of the words of the union. The random layout uses the first word as
// probability. The nth layout uses the words every, packet, and count.
const (
	statisticUnionProbability = 0
	statisticUnionEvery       = 0
	statisticUnionCount       = 2
)

func init() {
	registerMatchMaker(statisticMarshaler{})
}

// statisticMarshaler implements matchMaker for the statistic match.
type statisticMarshaler struct{}

// name implements matchMaker.name.
func (statisticMarshaler) name() string {
	return matcherNameStatistic
}

// revision implements matchMaker.revision.
func (statisticMarshaler) revision() uint8 {
	return statisticRevision0
}

// marshal implements matchMaker.marshal.
func (statisticMarshaler) marshal(mr matcher) []byte {
	sm := mr.(*StatisticMatcher)
	// Linux copies the user struct back unchanged and keeps the live counter
	// in the private master pointer. The master field stays zero here.
	data := make([]byte, statisticInfoSize)
	hostarch.ByteOrder.PutUint16(data[statisticOffMode:], sm.mode)
	hostarch.ByteOrder.PutUint16(data[statisticOffFlags:], sm.flags)
	for i, word := range sm.union {
		hostarch.ByteOrder.PutUint32(data[statisticOffUnion+4*i:], word)
	}
	buf := marshalEntryMatch(matcherNameStatistic, data)
	// marshalEntryMatch leaves Revision at 0. Iptables picks the user space
	// parser from this byte, so it must hold the revision of the rule.
	buf[revisionOffset] = statisticRevision0
	return buf
}

// unmarshal implements matchMaker.unmarshal.
func (statisticMarshaler) unmarshal(_ IDMapper, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	// WHY: Linux requires the exact aligned size.
	if want := bits.AlignUp(statisticInfoSize, 8); len(buf) != want {
		return nil, fmt.Errorf("statistic: buf has size %d, want %d", len(buf), want)
	}
	sm := &StatisticMatcher{
		mode:  hostarch.ByteOrder.Uint16(buf[statisticOffMode:]),
		flags: hostarch.ByteOrder.Uint16(buf[statisticOffFlags:]),
	}
	if sm.mode > statisticModeNth {
		return nil, fmt.Errorf("statistic: invalid mode %d", sm.mode)
	}
	if sm.flags&^statisticFlagInvert != 0 {
		return nil, fmt.Errorf("statistic: invalid flags 0x%x", sm.flags)
	}
	// The master pointer at offset 16 belongs to the kernel. Userspace sends
	// any value there, and the parser ignores it.
	for i := range sm.union {
		sm.union[i] = hostarch.ByteOrder.Uint32(buf[statisticOffUnion+4*i:])
	}
	// Each parsed rule gets its own counter. Userspace sets count to
	// every - packet, so the first matching packet is number packet + 1.
	sm.counter.Store(sm.union[statisticUnionCount])
	nflog("parsed statistic: mode %d flags 0x%x union %v", sm.mode, sm.flags, sm.union)
	return sm, nil
}

// StatisticMatcher matches a random share of the packets or every Nth packet
// of a rule.
//
// +stateify savable
type StatisticMatcher struct {
	mode  uint16
	flags uint16
	// union holds the user-visible words of the union in struct
	// xt_statistic_info exactly as parsed. Marshal writes them back
	// unchanged.
	union [statisticUnionLen]uint32

	// counter is the live position of the nth mode. Match advances it with
	// compare-and-swap, so concurrent packets of one rule need no lock.
	counter atomicbitops.Uint32
}

// name implements matcher.name.
func (*StatisticMatcher) name() string {
	return matcherNameStatistic
}

// revision implements matcher.revision.
func (*StatisticMatcher) revision() uint8 {
	return statisticRevision0
}

// Match implements stack.Matcher.Match. The match needs no packet data.
func (sm *StatisticMatcher) Match(stack.Hook, *stack.PacketBuffer, string, string) (bool, bool) {
	invert := sm.flags&statisticFlagInvert != 0
	switch sm.mode {
	case statisticModeRandom:
		hit := rand.Uint32()&statisticRandomMask < sm.union[statisticUnionProbability]
		return hit != invert, false
	case statisticModeNth:
		every := sm.union[statisticUnionEvery]
		for {
			old := sm.counter.Load()
			next := old + 1
			if old == every {
				next = 0
			}
			if sm.counter.CompareAndSwap(old, next) {
				return (old == every) != invert, false
			}
		}
	default:
		// Unmarshal rejects every other mode, so a rule never reaches here.
		return false, true
	}
}
