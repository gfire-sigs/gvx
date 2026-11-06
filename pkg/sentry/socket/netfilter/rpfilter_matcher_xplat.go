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

	"z.gfire.dev/gvx/pkg/bits"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the xt_rpfilter match (iptables "-m rpfilter"). Ref:
// include/uapi/linux/netfilter/xt_rpfilter.h and net/ipv4/netfilter/ipt_rpfilter.c.
// Calico adds "-m rpfilter --invert --validmark -j DROP" to the table raw to drop
// a packet of a workload that has a spoofed source address.

const matcherNameRPFilter = "rpfilter"

// Flags of struct xt_rpfilter_info.
const (
	rpfilterLoose       = 0x1
	rpfilterValidMark   = 0x2
	rpfilterAcceptLocal = 0x4
	rpfilterInvert      = 0x8
	rpfilterFlagMask    = rpfilterLoose | rpfilterValidMark | rpfilterAcceptLocal | rpfilterInvert
)

func init() {
	registerMatchMaker(rpfilterMarshaler{})
}

type rpfilterMarshaler struct{}

func (rpfilterMarshaler) name() string { return matcherNameRPFilter }

func (rpfilterMarshaler) revision() uint8 { return 0 }

func (rpfilterMarshaler) marshal(m matcher) []byte {
	return marshalEntryMatch(matcherNameRPFilter, []byte{m.(*RPFilterMatcher).flags})
}

func (rpfilterMarshaler) unmarshal(_ IDMapper, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	// struct xt_rpfilter_info holds one byte, which the entry pads to 8.
	if want := bits.AlignUp(1, 8); len(buf) != want {
		return nil, fmt.Errorf("rpfilter: buf has size %d, want %d", len(buf), want)
	}
	if buf[0]&^rpfilterFlagMask != 0 {
		return nil, fmt.Errorf("rpfilter: unknown flags %#x", buf[0])
	}
	return &RPFilterMatcher{flags: buf[0]}, nil
}

// RPFilterMatcher matches a packet whose source address passes the reverse
// path check.
type RPFilterMatcher struct {
	flags uint8
	stack *stack.Stack
}

func (*RPFilterMatcher) name() string { return matcherNameRPFilter }

func (*RPFilterMatcher) revision() uint8 { return 0 }

// bindStack implements stackBinder.bindStack.
func (m *RPFilterMatcher) bindStack(stk *stack.Stack) *syserr.Error {
	m.stack = stk
	return nil
}

// Match implements stack.Matcher.Match.
func (m *RPFilterMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, inNicName, _ string) (bool, bool) {
	src, dst, ok := packetAddresses(pkt)
	if !ok {
		return false, true
	}
	invert := m.flags&rpfilterInvert != 0
	if m.stack == nil {
		return invert, false
	}
	// The receive path sets the input NIC of the packet before PREROUTING, so a
	// packet needs no search by name.
	inNIC := pkt.InputNICID
	if inNIC == 0 {
		inNIC = m.stack.NICIDByName(inNicName)
	}
	if inNIC == 0 || m.stack.NICIsLoopback(inNIC) {
		return !invert, false
	}
	// A DHCP client sends from 0.0.0.0 to the broadcast address.
	if src.BitLen() != 0 && src.Unspecified() && (dst == header.IPv4Broadcast || header.IsV4MulticastAddress(dst)) {
		return !invert, false
	}
	var mark uint32
	if m.flags&rpfilterValidMark != 0 {
		mark = pkt.Mark
	}
	mode := stack.ReversePathStrict
	if m.flags&rpfilterLoose != 0 {
		mode = stack.ReversePathLoose
	}
	valid := m.stack.ReversePathValid(inNIC, src, dst, mark, pkt.NetworkProtocolNumber, mode, m.flags&rpfilterAcceptLocal != 0)
	return valid != invert, false
}
