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

	bitsutil "z.gfire.dev/gvx/pkg/bits"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	matcherNameSet = "set"

	// The revisions of the match that follow xt_set.c. The revisions 1 and 2
	// have the same layout.
	setMatchRevision1 uint8 = 1
	setMatchRevision2 uint8 = 2
	setMatchRevision3 uint8 = 3
	setMatchRevision4 uint8 = 4

	// The layout of struct xt_set_info: the index, the dimension, and the
	// flags. It has the size 4.
	setInfoOffIndex = 0
	setInfoOffDim   = 2
	setInfoOffFlags = 3
	setInfoSize     = 4

	// The sizes of the match data of each revision, without the final
	// padding that userspace adds.
	setMatchSizeV1 = setInfoSize
	setMatchSizeV3 = 44
	setMatchSizeV4 = 44

	// The offsets in struct xt_set_info_match_v3. Its counter conditions are
	// struct ip_set_counter_match0: the operation, then the value at the
	// next multiple of 8.
	setV3OffPacketsOp    = 8
	setV3OffPacketsValue = 16
	setV3OffBytesOp      = 24
	setV3OffBytesValue   = 32
	// setOffFlags is the offset of the flags of the revisions 3 and 4.
	setOffFlags = 40

	// The offsets in struct xt_set_info_match_v4. Its counter conditions
	// are struct ip_set_counter_match: the value, then the operation.
	setV4OffPacketsValue = 8
	setV4OffPacketsOp    = 16
	setV4OffBytesValue   = 24
	setV4OffBytesOp      = 32
)

func init() {
	for _, rev := range []uint8{setMatchRevision1, setMatchRevision2, setMatchRevision3, setMatchRevision4} {
		registerMatchMaker(setMarshaler{rev: rev})
	}
}

// setMatchSize returns the size of the match data of the revision.
func setMatchSize(rev uint8) int {
	switch rev {
	case setMatchRevision3:
		return setMatchSizeV3
	case setMatchRevision4:
		return setMatchSizeV4
	}
	return setMatchSizeV1
}

// setInfo is struct xt_set_info: the set and the way a packet selects the
// element of the set.
//
// +stateify savable
type setInfo struct {
	index ipset.ID
	dim   uint8
	flags uint8
}

func parseSetInfo(b []byte) setInfo {
	return setInfo{
		index: ipset.ID(hostarch.ByteOrder.Uint16(b[setInfoOffIndex:])),
		dim:   b[setInfoOffDim],
		flags: b[setInfoOffFlags],
	}
}

// setMarshaler implements matchMaker for the "set" match.
type setMarshaler struct {
	rev uint8
}

func (setMarshaler) name() string { return matcherNameSet }

func (m setMarshaler) revision() uint8 { return m.rev }

// marshal returns the bytes that unmarshal parsed. Linux also dumps the user
// struct unchanged.
func (m setMarshaler) marshal(mr matcher) []byte {
	sm := mr.(*SetMatcher)
	buf := marshalEntryMatch(matcherNameSet, sm.raw)
	buf[revisionOffset] = sm.rev
	return buf
}

func (m setMarshaler) unmarshal(_ IDMapper, _ *stack.Stack, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	if want := bitsutil.AlignUp(setMatchSize(m.rev), 8); len(buf) != want {
		return nil, fmt.Errorf("set rev%d: buf has size %d, want %d", m.rev, len(buf), want)
	}
	sm := &SetMatcher{
		rev:  m.rev,
		raw:  append([]byte(nil), buf...),
		info: parseSetInfo(buf),
	}
	order := hostarch.ByteOrder
	switch m.rev {
	case setMatchRevision3:
		sm.packetsOp, sm.packetsValue = buf[setV3OffPacketsOp], order.Uint64(buf[setV3OffPacketsValue:])
		sm.bytesOp, sm.bytesValue = buf[setV3OffBytesOp], order.Uint64(buf[setV3OffBytesValue:])
		sm.cmdFlags = order.Uint32(buf[setOffFlags:])
	case setMatchRevision4:
		sm.packetsOp, sm.packetsValue = buf[setV4OffPacketsOp], order.Uint64(buf[setV4OffPacketsValue:])
		sm.bytesOp, sm.bytesValue = buf[setV4OffBytesOp], order.Uint64(buf[setV4OffBytesValue:])
		sm.cmdFlags = order.Uint32(buf[setOffFlags:])
	}
	nflog("parsed set rev%d: %+v", m.rev, sm.info)
	return sm, nil
}

// SetMatcher is the "set" match: it tests the packet against an IP set.
//
// +stateify savable
type SetMatcher struct {
	rev uint8
	// raw is the user struct as parsed. Marshal returns it unchanged.
	raw  []byte
	info setInfo

	// The fields below belong to the revisions 3 and 4.
	packetsOp, bytesOp       uint8
	packetsValue, bytesValue uint64
	cmdFlags                 uint32

	// refs is the reference that bindStack takes. Match reads it without a
	// lock, because bindStack sets it before the rule is published.
	refs setRefs
}

func (*SetMatcher) name() string { return matcherNameSet }

func (m *SetMatcher) revision() uint8 { return m.rev }

// bindStack implements stackBinder.bindStack. It is the check function of the
// match in Linux.
func (m *SetMatcher) bindStack(stk *stack.Stack) *syserr.Error {
	return m.refs.acquire(stk, []setInfo{m.info}, false)
}

// releaseStack implements stackReleaser.releaseStack.
func (m *SetMatcher) releaseStack() { m.refs.release() }

// Match implements stack.Matcher.Match. It is set_match_v1, set_match_v3, and
// set_match_v4 of Linux.
func (m *SetMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	reg := m.refs.reg
	if reg == nil {
		return false, false
	}
	p, ok := ipsetPacket(pkt)
	if !ok {
		return false, true
	}
	opt := ipset.KOpt{
		Dim:     m.info.dim,
		Flags:   uint32(m.info.flags),
		Timeout: ipset.NoTimeout,
	}
	switch m.rev {
	case setMatchRevision3, setMatchRevision4:
		opt.CmdFlags = m.cmdFlags
		opt.PacketsOp, opt.PacketsValue = m.packetsOp, m.packetsValue
		opt.BytesOp, opt.BytesValue = m.bytesOp, m.bytesValue
		if m.packetsOp != ipset.CounterNone || m.bytesOp != ipset.CounterNone {
			opt.CmdFlags |= ipset.FlagMatchCounters
		}
	default:
		if opt.Flags&ipset.KReturnNomatch != 0 {
			opt.CmdFlags |= ipset.FlagReturnNomatch
		}
	}
	return setTest(reg, m.info, &p, &opt), false
}

// setTest is match_set of Linux: the result of the test, inverted when the
// flags of the set ask for it.
func setTest(reg *ipset.Registry, info setInfo, p *ipset.Packet, opt *ipset.KOpt) bool {
	return (reg.Test(info.index, p, opt) > 0) != (uint32(info.flags)&ipset.KInvMatch != 0)
}
