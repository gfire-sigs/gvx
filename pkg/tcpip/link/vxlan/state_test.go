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

package vxlan

import (
	"bytes"
	"context"
	"testing"
	"time"
	"weak"

	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/link/ethernet"
	"z.gfire.dev/gvx/pkg/tcpip/link/pipe"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

func TestStateRoundTripEndpointFDBAndOverlayTraffic(t *testing.T) {
	cfgA := Config{VNI: 42, Port: 4789, Learning: true}
	cfgB := Config{
		VNI:           42,
		Port:          4789,
		Learning:      true,
		AgeingSeconds: 600,
		Limit:         64,
		PortLow:       40000,
		PortHigh:      40009,
	}
	a, b := newNodes(t, cfgA, cfgB)
	connect(t, a, b)

	extraMAC := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x77")
	extraRemote := Remote{IP: ip4(10, 0, 0, 99), Port: 4789, VNI: 42}
	if err := b.vxlan.FDBUpdate(extraMAC, NUDPermanent, NTFSelf, extraRemote, UpdateMode{Create: true, Excl: true}); err != nil {
		t.Fatalf("FDBUpdate(extraMAC): %v", err)
	}

	// Remove B's static FDB entry for A so B learns A dynamically before save.
	if err := b.vxlan.FDBDelete(a.vxlan.LinkAddress(), Remote{}); err != nil {
		t.Fatalf("FDBDelete(A): %v", err)
	}
	if !echo(t, a, b, 9000, "before-save", 5*time.Second) {
		t.Fatal("overlay datagram did not cross before save")
	}

	aMAC := a.vxlan.LinkAddress()
	bMAC := b.vxlan.LinkAddress()
	wsOldB := weak.Make(b.stack)

	b.stack.Pause()
	var buf bytes.Buffer
	saved := []any{b.stack, b.vxlan}
	if _, err := state.Save(context.Background(), &buf, &saved); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	// Shut down the pre-save nodes so their sockets release global entries.
	a.stack.Close()
	a.stack.Wait()
	CloseStack(a.stack)
	a.vxlan.Close()

	b.stack.Close()
	b.stack.Wait()
	CloseStack(b.stack)
	b.vxlan.Close()

	if nics, socks := countGlobalVxlanEntriesForStacks(wsOldB); nics != 0 || socks != 0 {
		t.Fatalf("pre-save stack global entries after close = (%d nics, %d sockets), want (0, 0)", nics, socks)
	}

	var loaded []any
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoredStk := loaded[0].(*stack.Stack)
	restoredVxlan := loaded[1].(*Endpoint)
	wsRestoredB := weak.Make(restoredStk)
	t.Cleanup(func() {
		restoredStk.Close()
		restoredStk.Wait()
		CloseStack(restoredStk)
		restoredVxlan.Close()
	})

	// Build a fresh peer node with the same MAC as A and link it to restoredStk.
	pa, pb := pipe.New("\x02\x00\x00\x00\x02\x01", "\x02\x00\x00\x00\x02\x02", 1514)

	cfgStk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	if err := cfgStk.CreateNIC(underlayNIC, ethernet.New(pb)); err != nil {
		t.Fatalf("cfgStk.CreateNIC(underlay): %v", err)
	}
	if err := cfgStk.AddProtocolAddress(underlayNIC, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: ip4(10, 0, 0, 2), PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("cfgStk.AddProtocolAddress(underlay): %v", err)
	}
	cfgStk.SetRouteTable([]tcpip.Route{
		subnetRoute(ip4(10, 0, 0, 2), underlayNIC),
	})
	restoredStk.ResetConfig()
	restoredStk.ReplaceConfig(cfgStk)
	restoredStk.Restore()

	peerStk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	t.Cleanup(func() {
		peerStk.Close()
		peerStk.Wait()
		CloseStack(peerStk)
	})
	if err := peerStk.CreateNIC(underlayNIC, ethernet.New(pa)); err != nil {
		t.Fatalf("peerStk.CreateNIC(underlay): %v", err)
	}
	if err := peerStk.AddProtocolAddress(underlayNIC, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: ip4(10, 0, 0, 1), PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("peerStk.AddProtocolAddress(underlay): %v", err)
	}
	peerEp, err := New(peerStk, Config{
		ID:       overlayNIC,
		VNI:      42,
		Port:     4789,
		Local:    ip4(10, 0, 0, 1),
		Address:  aMAC,
		Learning: true,
	})
	if err != nil {
		t.Fatalf("New(peerEp): %v", err)
	}
	t.Cleanup(peerEp.Close)
	if err := peerStk.CreateNIC(overlayNIC, peerEp); err != nil {
		t.Fatalf("peerStk.CreateNIC(vxlan): %v", err)
	}
	if err := peerStk.AddProtocolAddress(overlayNIC, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: ip4(192, 168, 1, 1), PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("peerStk.AddProtocolAddress(overlay): %v", err)
	}
	peerStk.SetRouteTable([]tcpip.Route{
		subnetRoute(ip4(10, 0, 0, 1), underlayNIC),
		subnetRoute(ip4(192, 168, 1, 1), overlayNIC),
	})
	if err := peerStk.AddStaticNeighbor(overlayNIC, ipv4.ProtocolNumber, ip4(192, 168, 1, 2), bMAC); err != nil {
		t.Fatalf("peerStk.AddStaticNeighbor: %v", err)
	}
	if err := peerEp.FDBUpdate(bMAC, NUDPermanent, NTFSelf, Remote{IP: ip4(10, 0, 0, 2), Port: 4789, VNI: 42}, UpdateMode{Create: true}); err != nil {
		t.Fatalf("peerEp.FDBUpdate: %v", err)
	}

	gotCfg := restoredVxlan.Config()
	if gotCfg.VNI != 42 || gotCfg.Port != 4789 || !gotCfg.Learning || gotCfg.Address != bMAC || gotCfg.Limit != 64 || gotCfg.PortLow != 40000 || gotCfg.PortHigh != 40009 {
		t.Fatalf("restored Config = %+v, want VNI 42, Port 4789, Learning true, MAC %v", gotCfg, bMAC)
	}

	var foundExtra, foundLearned bool
	for _, entry := range restoredVxlan.FDB() {
		switch entry.MAC {
		case extraMAC:
			foundExtra = len(entry.Remotes) == 1 && entry.Remotes[0] == extraRemote && entry.State == NUDPermanent
		case aMAC:
			foundLearned = len(entry.Remotes) == 1 && entry.Remotes[0].IP == ip4(10, 0, 0, 1) && entry.State == NUDReachable
		}
	}
	if !foundExtra || !foundLearned {
		t.Fatalf("restored FDB = %+v, want permanent extra entry (%v) and learned peer entry (%v)", restoredVxlan.FDB(), foundExtra, foundLearned)
	}

	peerNode := &node{stack: peerStk, vxlan: peerEp, underlay: ip4(10, 0, 0, 1), overlay: ip4(192, 168, 1, 1)}
	restoredNode := &node{stack: restoredStk, vxlan: restoredVxlan, underlay: ip4(10, 0, 0, 2), overlay: ip4(192, 168, 1, 2)}

	if !echo(t, peerNode, restoredNode, 9010, "inbound-after-restore", 5*time.Second) {
		t.Fatal("inbound overlay datagram did not reach restored VXLAN endpoint")
	}
	if !echo(t, restoredNode, peerNode, 9011, "outbound-after-restore", 5*time.Second) {
		t.Fatal("outbound overlay datagram from restored VXLAN endpoint did not reach peer")
	}

	if nics, socks := countGlobalVxlanEntriesForStacks(wsRestoredB); nics != 1 || socks != 1 {
		t.Fatalf("restored stack active global entries = (%d nics, %d sockets), want (1, 1)", nics, socks)
	}
	restoredStk.Close()
	restoredStk.Wait()
	CloseStack(restoredStk)
	restoredVxlan.Close()
	if nics, socks := countGlobalVxlanEntriesForStacks(wsRestoredB); nics != 0 || socks != 0 {
		t.Fatalf("restored stack leaked global entries after close = (%d nics, %d sockets), want (0, 0)", nics, socks)
	}
}
