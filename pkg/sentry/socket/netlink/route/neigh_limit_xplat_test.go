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

package route

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func newNeighTestStack(t *testing.T) *netstack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol, ipv6.NewProtocol},
	})
	t.Cleanup(s.Close)
	ep := channel.New(16, 1500, "\x02\x00\x00\x00\x00\x01")
	ep.LinkEPCapabilities |= stack.CapabilityResolutionRequired
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	return &netstack.Stack{Stack: s}
}

// TestStaticNeighborsHaveNoLimit adds more NUD_PERMANENT entries than the old
// cap of 65,536 for one link and one family. Linux has no cap for them: it
// keeps them off the garbage collection list.
func TestStaticNeighborsHaveNoLimit(t *testing.T) {
	st := newNeighTestStack(t)
	const count = 70000
	for _, family := range []uint8{linux.AF_INET, linux.AF_INET6} {
		for i := range count {
			dst := nlmsg.BytesView{172, byte(16 + i>>16), byte(i >> 8), byte(i)}
			if family == linux.AF_INET6 {
				dst = nlmsg.BytesView{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
			}
			attrs := map[uint16]nlmsg.BytesView{
				ndaDst:    dst,
				ndaLLAddr: {2, 0, 0, 0, byte(i >> 8), byte(i)},
			}
			nd := ndmsg{family: family, ifindex: 1, state: nudPermanent}
			if err := newNeigh(st, nd, attrs, linux.NLM_F_CREATE|linux.NLM_F_EXCL); err != nil {
				t.Fatalf("family %d: entry %d: %v", family, i, err)
			}
		}
		proto := ipv4.ProtocolNumber
		if family == linux.AF_INET6 {
			proto = ipv6.ProtocolNumber
		}
		entries, terr := st.Stack.Neighbors(1, proto)
		if terr != nil || len(entries) != count {
			t.Errorf("family %d: entries = %d, error %v, want %d", family, len(entries), terr, count)
		}
	}
}
