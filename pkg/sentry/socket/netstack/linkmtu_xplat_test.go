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

package netstack

import (
	"testing"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/veth"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// newVethNICs creates two NICs on one tcpip stack, one for each end of a veth
// pair, as newVeth does.
func newVethNICs(t *testing.T) (*stack.Stack, [2]tcpip.NICID) {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	t.Cleanup(func() { s.Close() })
	a, b := veth.NewPair(defaultMTU, veth.DefaultBacklogSize)
	var ids [2]tcpip.NICID
	for i, end := range []*veth.Endpoint{a, b} {
		id := tcpip.NICID(i + 1)
		ids[i] = id
		opts := stack.NICOptions{Name: []string{"veth0", "veth1"}[i], Kind: "veth", MinMTU: ethernetMinMTU, MaxMTU: ethernetMaxMTU}
		if err := s.CreateNICWithOptions(id, newVethNICEndpoint(end), opts); err != nil {
			t.Fatalf("CreateNICWithOptions(%d): %v", id, err)
		}
	}
	return s, ids
}

func TestVethNICKeepsGVisorGSO(t *testing.T) {
	s, _ := newVethNICs(t)
	for _, name := range []string{"veth0", "veth1"} {
		gso, ok := s.GetLinkEndpointByName(name).(stack.GSOEndpoint)
		if !ok {
			t.Fatalf("the link of %s does not implement stack.GSOEndpoint, so TCP cannot send large segments", name)
		}
		if got := gso.SupportedGSO(); got != stack.GVisorGSOSupported {
			t.Errorf("%s SupportedGSO = %v, want GVisorGSOSupported", name, got)
		}
		if got := gso.GSOMaxSize(); got != tcpip.GVisorGSOMaxSize {
			t.Errorf("%s GSOMaxSize = %d, want %d", name, got, tcpip.GVisorGSOMaxSize)
		}
	}
}

func TestEachVethEndHasItsOwnMTU(t *testing.T) {
	s, ids := newVethNICs(t)
	mtu := func(id tcpip.NICID) uint32 { return s.NICInfo()[id].MTU }
	if got := [2]uint32{mtu(ids[0]), mtu(ids[1])}; got != [2]uint32{defaultMTU, defaultMTU} {
		t.Fatalf("MTU of a new veth pair = %v, want %d on both ends", got, defaultMTU)
	}
	if err := s.SetNICMTU(ids[0], 1400); err != nil {
		t.Fatal(err)
	}
	if got := [2]uint32{mtu(ids[0]), mtu(ids[1])}; got != [2]uint32{1400, defaultMTU} {
		t.Errorf("MTU after the change of the first end = %v, want [1400 %d]", got, defaultMTU)
	}
	if err := s.SetNICMTU(ids[1], 9000); err != nil {
		t.Fatal(err)
	}
	if got := [2]uint32{mtu(ids[0]), mtu(ids[1])}; got != [2]uint32{1400, 9000} {
		t.Errorf("MTU after the change of the second end = %v, want [1400 9000]", got)
	}
	if err := s.SetNICMTU(ids[0], header.IPv4MinimumMTU-1); err == nil {
		t.Error("SetNICMTU below 68 succeeded")
	}
	if got := mtu(ids[0]); got != 1400 {
		t.Errorf("MTU after the refused change = %d, want 1400", got)
	}
}
