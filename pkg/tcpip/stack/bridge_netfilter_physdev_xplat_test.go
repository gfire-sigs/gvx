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

package stack_test

import (
	"slices"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// The tests of this file check the bridge information that the physdev match
// reads. A recording matcher sits first in each chain of the mangle table. It
// notes what the packet carries in each hook and never matches.

// hookRecord is what the recorder saw in one hook.
type hookRecord struct {
	hook     stack.Hook
	bridged  bool
	from, to string
}

// hookRecorder is a stack.Matcher that records the bridge information of the
// packets for one destination address.
type hookRecorder struct {
	dst tcpip.Address

	mu      sync.Mutex
	records []hookRecord
}

// Match implements stack.Matcher.Match.
func (r *hookRecorder) Match(hook stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	if pkt.Network().DestinationAddress() != r.dst {
		return false, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, hookRecord{hook: hook, bridged: pkt.Bridged, from: pkt.BridgedFrom, to: pkt.BridgedTo})
	return false, false
}

func (r *hookRecorder) seen() []hookRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.records)
}

// installRecorder puts a rule with the recorder at the start of each chain of
// the mangle table.
func installRecorder(s *stack.Stack, r *hookRecorder) {
	table := s.IPTables().GetTable(stack.MangleID, false)
	var rules []stack.Rule
	chains, underflows := table.BuiltinChains, table.Underflows
	for idx, rule := range table.Rules {
		for hook, start := range table.BuiltinChains {
			if start == idx {
				chains[hook] = len(rules)
				rules = append(rules, stack.Rule{
					Filter:   stack.EmptyFilter4(),
					Matchers: []stack.Matcher{r},
					Target:   &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber},
				})
			}
		}
		for hook, underflow := range table.Underflows {
			if underflow == idx {
				underflows[hook] = len(rules)
			}
		}
		rules = append(rules, rule)
	}
	table.Rules, table.BuiltinChains, table.Underflows = rules, chains, underflows
	s.IPTables().ForceReplaceTable(stack.MangleID, table, false)
}

// TestBridgeNetfilterMarksBridgedFrames checks that a frame which the bridge
// switches between two ports carries the bridge information in the hooks. The
// PREROUTING hook knows the port of arrival. The FORWARD and POSTROUTING hooks
// also know the port that the forwarding database names.
func TestBridgeNetfilterMarksBridgedFrames(t *testing.T) {
	n := newNFStack(t, tcpip.FullAddress{Addr: nfBridgeIP, Port: nfTargetPort})
	rec := &hookRecorder{dst: nfPeerIP}
	installRecorder(n.stack, rec)
	n.learn()
	n.sendDatagramTo(macs[2], nfPeerIP, 9000, "bridged")
	if f := nextFrame(t, n.hosts[2]); f.payload != "bridged" {
		t.Fatalf("frame at host 2 = %+v, want the datagram", f)
	}

	from, to := n.stack.FindNICNameFromID(10), n.stack.FindNICNameFromID(12)
	if from == "" || to == "" || from == to {
		t.Fatalf("port names = %q and %q, want two different names", from, to)
	}
	want := []hookRecord{
		{hook: stack.Prerouting, bridged: true, from: from},
		{hook: stack.Forward, bridged: true, from: from, to: to},
		{hook: stack.Postrouting, bridged: true, from: from, to: to},
	}
	if got := rec.seen(); !slices.Equal(got, want) {
		t.Errorf("hooks saw %+v, want %+v", got, want)
	}
}

// TestBridgeNetfilterDoesNotMarkRoutedPackets checks that a frame which the IP
// layer of the bridge routes to another link has no bridge information.
func TestBridgeNetfilterDoesNotMarkRoutedPackets(t *testing.T) {
	n := newNFStack(t, tcpip.FullAddress{Addr: nfBridgeIP, Port: nfTargetPort})
	rec := &hookRecorder{dst: nfRemoteIP}
	installRecorder(n.stack, rec)
	n.learn()
	// The frame goes to the Ethernet address of the bridge, so the bridge
	// gives it to its IP layer, which routes it to the router link.
	n.sendDatagramTo(n.mac, nfRemoteIP, 9000, "routed")
	if f := nextFrame(t, n.remote); f.payload != "routed" {
		t.Fatalf("frame behind the route = %+v, want the datagram", f)
	}

	got := rec.seen()
	if len(got) == 0 {
		t.Fatalf("no hook saw the routed packet")
	}
	for _, r := range got {
		if r.bridged || r.from != "" || r.to != "" {
			t.Errorf("hook %v saw bridge information %+v on a routed packet, want none", r.hook, r)
		}
	}
	if !slices.ContainsFunc(got, func(r hookRecord) bool { return r.hook == stack.Forward }) {
		t.Errorf("hooks saw %+v, want the FORWARD hook among them", got)
	}
}
