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

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/bits"
	"z.gfire.dev/gvx/pkg/marshal"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the xt_connmark match (iptables "-m connmark"). Ref:
// net/netfilter/xt_connmark.c. The match reads the same struct as the match
// mark, struct xt_connmark_mtinfo1.

const (
	matcherNameConnmark = "connmark"
	connmarkRevision    = 1
)

func init() {
	registerMatchMaker(connmarkMarshaler{})
}

type connmarkMarshaler struct{}

func (connmarkMarshaler) name() string { return matcherNameConnmark }

func (connmarkMarshaler) revision() uint8 { return connmarkRevision }

func (connmarkMarshaler) marshal(mr matcher) []byte {
	m := mr.(*ConnmarkMatcher)
	info := linux.XTMarkMtinfo1{Mark: m.mark, Mask: m.mask}
	if m.invert {
		info.Invert = 1
	}
	return marshalEntryMatch(matcherNameConnmark, marshal.Marshal(&info))
}

func (connmarkMarshaler) unmarshal(_ IDMapper, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	// Linux requires the exact aligned size.
	if want := bits.AlignUp(linux.SizeOfXTMarkMtinfo1, 8); len(buf) != want {
		return nil, fmt.Errorf("connmark: buf has size %d, want %d", len(buf), want)
	}
	var info linux.XTMarkMtinfo1
	info.UnmarshalUnsafe(buf)
	return &ConnmarkMatcher{mark: info.Mark, mask: info.Mask, invert: info.Invert != 0}, nil
}

// ConnmarkMatcher matches the mark of the connection of a packet.
type ConnmarkMatcher struct {
	mark   uint32
	mask   uint32
	invert bool
}

// NewConnmarkMatcher creates a ConnmarkMatcher.
func NewConnmarkMatcher(mark, mask uint32, invert bool) *ConnmarkMatcher {
	return &ConnmarkMatcher{mark: mark, mask: mask, invert: invert}
}

func (*ConnmarkMatcher) name() string { return matcherNameConnmark }

func (*ConnmarkMatcher) revision() uint8 { return connmarkRevision }

// Match implements stack.Matcher.Match. Like Linux connmark_mt, a packet
// without a tracked connection never matches, even with the inversion.
func (m *ConnmarkMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	if !pkt.IsConnTrackConfigured() {
		return false, false
	}
	return ((pkt.ConnMark() & m.mask) == m.mark) != m.invert, false
}
