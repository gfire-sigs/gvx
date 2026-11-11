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
	"bytes"
	goContext "context"
	"testing"

	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/link/veth"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func configureNetstackNICs(t *testing.T, inner *stack.Stack) {
	t.Helper()
	if err := inner.CreateNICWithOptions(1, loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
		t.Fatalf("CreateNICWithOptions(lo): %s", err)
	}
	a, b := veth.NewPair(defaultMTU, veth.DefaultBacklogSize)
	t.Cleanup(func() { b.Close() })
	if err := inner.CreateNICWithOptions(2, newVethNICEndpoint(a), stack.NICOptions{
		Name:   "eth0",
		Kind:   "veth",
		MinMTU: ethernetMinMTU,
		MaxMTU: ethernetMaxMTU,
	}); err != nil {
		t.Fatalf("CreateNICWithOptions(eth0): %s", err)
	}
	if err := inner.CreateNICWithOptions(3, loopback.New(), stack.NICOptions{Name: "uplink"}); err != nil {
		t.Fatalf("CreateNICWithOptions(uplink): %s", err)
	}

	ethAddr := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	uplinkAddr := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	if err := inner.AddProtocolAddress(2, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: ethAddr, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(eth0): %s", err)
	}
	if err := inner.AddProtocolAddress(3, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: uplinkAddr, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(uplink): %s", err)
	}
	inner.AddRoute(tcpip.Route{
		Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 0, 0, 0}), PrefixLen: 24}.Subnet(),
		NIC:         2,
	})
	inner.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		Gateway:     tcpip.AddrFrom4([4]byte{192, 0, 2, 254}),
		NIC:         3,
	})
}

func TestNetstackXplatStateAndPoliciesSurviveSaveLoad(t *testing.T) {
	inner := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	defer inner.Close()
	configureNetstackNICs(t, inner)
	// Also add a tun-preserved veth link so vethLink and hostFilterEndpoint
	// exercise direct serialization in preservedNICs.
	tunA, tunB := veth.NewPair(defaultMTU, veth.DefaultBacklogSize)
	defer tunB.Close()
	if err := inner.CreateNICWithOptions(4, newVethNICEndpoint(tunA), stack.NICOptions{
		Name:   "veth-preserved",
		Kind:   "tun",
		MinMTU: ethernetMinMTU,
		MaxMTU: ethernetMaxMTU,
	}); err != nil {
		t.Fatalf("CreateNICWithOptions(veth-preserved): %s", err)
	}

	s := NewStack(inner, 1)
	s.SetUnprivilegedPortStart(80)
	if err := s.SetForwardingSwitch(ipv4.ProtocolNumber, false /* isDefault */, true); err != nil {
		t.Fatalf("SetForwardingSwitch: %v", err)
	}
	s.SetSysctlValue(ConfDirIPv4+"/all/proxy_arp", "1")
	s.SetSysctlValue(ConfDirIPv4+"/all/src_valid_mark", "1")
	s.SetBridgeNetfilter(header.IPv4ProtocolNumber, false)

	s.SetRPFilterAll(1)
	s.SetRPFilterDefault(2)
	if err := s.SetLinkRPFilter(2, 1); err != nil {
		t.Fatalf("SetLinkRPFilter(2): %v", err)
	}
	if err := s.SetLinkConfValue(2, ConfDirIPv4, "arp_ignore", 2); err != nil {
		t.Fatalf("SetLinkConfValue(2): %v", err)
	}

	_, _, activeBefore, _ := getFeatures(t, s, "eth0")
	toggleBit := uint64(1) << bitHWCsum
	if _, err := setFeatures(s, "eth0", true /* admin */, toggleBit, (activeBefore&toggleBit) == 0); err != nil {
		t.Fatalf("setFeatures(eth0): %v", err)
	}
	_, wantRequested, wantActive, _ := getFeatures(t, s, "eth0")

	inner.SetRemoveConf(true)
	ctx := goContext.Background()
	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &s); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	var restored *Stack
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer restored.Stack.Close()

	replacement := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	defer replacement.Close()
	configureNetstackNICs(t, replacement)
	restored.Stack.ReplaceConfig(replacement)
	restored.Stack.Restore()
	if err := restored.SetForwarding(ipv4.ProtocolNumber, restored.Forwarding(ipv4.ProtocolNumber, false)); err != nil {
		t.Fatalf("restored SetForwarding: %v", err)
	}

	if got := restored.UnprivilegedPortStart(); got != 80 {
		t.Errorf("UnprivilegedPortStart = %d, want 80", got)
	}
	if !restored.Forwarding(ipv4.ProtocolNumber, false) {
		t.Error("Forwarding(ipv4, all) = false, want true")
	}
	if restored.BridgeNetfilter(header.IPv4ProtocolNumber) {
		t.Error("BridgeNetfilter(ipv4) = true, want false")
	}
	if restored.RPFilterAll() != 1 || restored.RPFilterDefault() != 2 {
		t.Errorf("RPFilter all=%d default=%d, want 1 and 2", restored.RPFilterAll(), restored.RPFilterDefault())
	}
	requireRPFilter(t, restored, 2, 1, 1)
	requireRPFilter(t, restored, 3, 2, 2)

	arpIgnore, err := restored.LinkConfValue(2, ConfDirIPv4, "arp_ignore", 0)
	if err != nil || arpIgnore != 2 {
		t.Errorf("LinkConfValue(2, arp_ignore) = (%d, %v), want (2, nil)", arpIgnore, err)
	}

	_, gotRequested, gotActive, _ := getFeatures(t, restored, "eth0")
	if gotRequested != wantRequested || gotActive != wantActive {
		t.Errorf("restored ethtool features = (req=%#x, active=%#x), want (req=%#x, active=%#x)",
			gotRequested, gotActive, wantRequested, wantActive)
	}

	// Verify that afterLoad rebound proxyARPEnabled and rpFilterPolicy on inner stack.Stack.
	ethAddr := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	sender := tcpip.AddrFrom4([4]byte{10, 0, 0, 50})
	target := tcpip.AddrFrom4([4]byte{198, 51, 100, 9})
	if !restored.Stack.ProxyARPReply(2, sender, target) {
		t.Error("ProxyARPReply after restore = false, want true with rebound proxy_arp policy")
	}
	spoofed := tcpip.AddrFrom4([4]byte{203, 0, 113, 9})
	if restored.Stack.SourceAddressValid(2, spoofed, ethAddr, 0, header.UDPProtocolNumber) {
		t.Error("SourceAddressValid accepted a spoofed source on strict rp_filter link after restore")
	}
	if !restored.Stack.SourceAddressValid(2, sender, ethAddr, 0, header.UDPProtocolNumber) {
		t.Error("SourceAddressValid rejected a valid subnet source on link 2 after restore")
	}
}
