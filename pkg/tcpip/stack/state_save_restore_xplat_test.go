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
	"bytes"
	"context"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/checksum"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func buildIPv4UDPPacket(src, dst tcpip.Address, srcPort, dstPort uint16, payload []byte) *stack.PacketBuffer {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.IPv4MinimumSize + header.UDPMinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)),
		Protocol:    uint8(header.UDPProtocolNumber),
		TTL:         64,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	udp.SetChecksum(^udp.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(header.UDPMinimumSize+len(payload))),
		pkt.Data().Checksum(),
	)))
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	return pkt
}

func TestConnTrackNATSaveLoadPreservesSessionAndCount(t *testing.T) {
	clock := faketime.NewManualClock()
	clock.Advance(10 * time.Second)

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		Clock:            clock,
	})
	defer s.Close()

	clientAddr := fibAddr(10, 0, 0, 2)
	snatAddr := fibAddr(203, 0, 113, 10)
	serverAddr := fibAddr(198, 51, 100, 5)
	const (
		clientPort = uint16(41000)
		snatPort   = uint16(50001)
		serverPort = uint16(53)
		wantMark   = uint32(0xdeadbeef)
	)

	ep := channel.New(8, 1500, "")
	if err := s.CreateNICWithOptions(1, ep, stack.NICOptions{Name: "eth0", Kind: "tun"}); err != nil {
		t.Fatalf("CreateNICWithOptions: %s", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: snatAddr, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})

	s.SetConntrackTimeout(stack.ConntrackTimeoutUDP, 90*time.Second)
	s.SetConntrackTimeout(stack.ConntrackTimeoutUDPStream, 300*time.Second)
	s.SetConntrackTCPMaxRetrans(7)
	s.SetConntrackLimit(stack.NewConntrackLimit(128))

	natFilter := stack.EmptyFilter4()
	natFilter.Src = clientAddr
	natFilter.SrcMask = fibAddr(255, 255, 255, 255)
	dynFilter := stack.EmptyFilter4()
	dynFilter.Src = fibAddr(10, 0, 0, 3)
	dynFilter.SrcMask = fibAddr(255, 255, 255, 255)

	natTable := stack.Table{
		Rules: []stack.Rule{
			{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{
				Filter: natFilter,
				Target: &stack.SNATTarget{
					Addr:            snatAddr,
					Port:            snatPort,
					NetworkProtocol: header.IPv4ProtocolNumber,
					ChangeAddress:   true,
					ChangePort:      true,
				},
			},
			{
				Filter: dynFilter,
				Target: &stack.SNATTarget{
					Addr:            snatAddr,
					Port:            0,
					NetworkProtocol: header.IPv4ProtocolNumber,
					ChangeAddress:   true,
					ChangePort:      true,
				},
			},
			{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			{Filter: stack.EmptyFilter4(), Target: &stack.ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
		},
		BuiltinChains: [stack.NumHooks]int{
			stack.Prerouting:  0,
			stack.Input:       1,
			stack.Forward:     stack.HookUnset,
			stack.Output:      2,
			stack.Postrouting: 3,
		},
		Underflows: [stack.NumHooks]int{
			stack.Prerouting:  0,
			stack.Input:       1,
			stack.Forward:     stack.HookUnset,
			stack.Output:      2,
			stack.Postrouting: 5,
		},
	}
	s.IPTables().ReplaceTable(stack.NATID, natTable, false /* ipv6 */)

	rt, err := s.FindRoute(1, snatAddr, serverAddr, ipv4.ProtocolNumber, false)
	if err != nil {
		t.Fatalf("FindRoute: %s", err)
	}
	defer rt.Release()

	// Send initial outbound packet and mark its connection, then finalize in Postrouting.
	out1 := buildIPv4UDPPacket(clientAddr, serverAddr, clientPort, serverPort, []byte("ping"))
	if !s.IPTables().CheckOutput(out1, rt, "eth0") {
		t.Fatal("CheckOutput dropped initial outbound packet")
	}
	out1.SetConnMark(wantMark)
	if !s.IPTables().CheckPostrouting(out1, rt, nil, "eth0") {
		t.Fatal("CheckPostrouting dropped initial outbound packet")
	}
	if gotSrc := header.IPv4(out1.NetworkHeader().Slice()).SourceAddress(); gotSrc != snatAddr {
		t.Fatalf("SNAT source address = %s, want %s", gotSrc, snatAddr)
	}
	if gotPort := header.UDP(out1.TransportHeader().Slice()).SourcePort(); gotPort != snatPort {
		t.Fatalf("SNAT source port = %d, want %d", gotPort, snatPort)
	}
	out1.DecRef()

	// Send inbound reply packet, then advance past udpStreamDelay (2s) and send a
	// follow-up packet so Linux UDP tracking promotes the flow to assured (300s).
	netEP, err := s.GetNetworkEndpoint(1, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("GetNetworkEndpoint: %s", err)
	}
	addrEP := netEP.(stack.AddressableEndpoint)
	in1 := buildIPv4UDPPacket(serverAddr, snatAddr, serverPort, snatPort, []byte("pong"))
	if !s.IPTables().CheckPrerouting(in1, addrEP, "eth0") {
		t.Fatal("CheckPrerouting dropped reply packet")
	}
	if !s.IPTables().CheckInput(in1, "eth0") {
		t.Fatal("CheckInput dropped reply packet")
	}
	if gotDst := header.IPv4(in1.NetworkHeader().Slice()).DestinationAddress(); gotDst != clientAddr {
		t.Fatalf("reverse NAT destination = %s, want %s", gotDst, clientAddr)
	}
	if gotPort := header.UDP(in1.TransportHeader().Slice()).DestinationPort(); gotPort != clientPort {
		t.Fatalf("reverse NAT destination port = %d, want %d", gotPort, clientPort)
	}
	in1.DecRef()

	clock.Advance(3 * time.Second)
	outAssured := buildIPv4UDPPacket(clientAddr, serverAddr, clientPort, serverPort, []byte("stream"))
	if !s.IPTables().CheckOutput(outAssured, rt, "eth0") || !s.IPTables().CheckPostrouting(outAssured, rt, nil, "eth0") {
		t.Fatal("outbound stream-promotion packet dropped")
	}
	outAssured.DecRef()

	if got := s.ConntrackCount(); got != 1 {
		t.Fatalf("ConntrackCount before save = %d, want 1", got)
	}

	// Advance clock by 60s before checkpoint so 240s remain on the 300s stream timer.
	clock.Advance(60 * time.Second)

	s.SetRemoveConf(true)
	ctx := context.Background()
	bundle := []any{s, s.IPTables()}
	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &bundle); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	var restoredBundle []any
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restoredBundle); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restored := restoredBundle[0].(*stack.Stack)
	restoredIPT := restoredBundle[1].(*stack.IPTables)
	defer restored.Close()
	restored.SetIPTables(restoredIPT)
	restored.Restore()

	if got := restored.ConntrackCount(); got != 1 {
		t.Fatalf("ConntrackCount after load = %d, want 1", got)
	}
	if lim := restored.ConntrackLimit(); lim == nil || lim.Max() != 128 {
		t.Fatalf("restored ConntrackLimit = %v, want Max=128", lim)
	}
	if got := restored.ConntrackTimeout(stack.ConntrackTimeoutUDPStream); got != 300*time.Second {
		t.Fatalf("restored UDPStream timeout = %v, want 300s", got)
	}
	if got := restored.ConntrackTCPMaxRetrans(); got != 7 {
		t.Fatalf("restored ConntrackTCPMaxRetrans = %d, want 7", got)
	}

	entries := restored.ConntrackEntries()
	if len(entries) != 1 {
		t.Fatalf("ConntrackEntries after load = %d, want 1 (session must not expire on load)", len(entries))
	}
	if entries[0].Mark != wantMark {
		t.Errorf("restored entry Mark = %#x, want %#x", entries[0].Mark, wantMark)
	}
	if entries[0].Status&stack.ConntrackStatusAssured == 0 {
		t.Errorf("restored entry Status = %#x, want ConntrackStatusAssured set", entries[0].Status)
	}
	if entries[0].Timeout < 239*time.Second || entries[0].Timeout > 240*time.Second {
		t.Errorf("restored entry Timeout = %v, want ~240s", entries[0].Timeout)
	}

	restoredRt, err := restored.FindRoute(1, snatAddr, serverAddr, ipv4.ProtocolNumber, false)
	if err != nil {
		t.Fatalf("restored FindRoute: %s", err)
	}
	defer restoredRt.Release()

	// Verify subsequent packet on existing NAT flow reuses translation and mark.
	out2 := buildIPv4UDPPacket(clientAddr, serverAddr, clientPort, serverPort, []byte("next"))
	if !restored.IPTables().CheckOutput(out2, restoredRt, "eth0") {
		t.Fatal("restored CheckOutput dropped existing flow packet")
	}
	if gotMark := out2.ConnMark(); gotMark != wantMark {
		t.Errorf("restored packet ConnMark = %#x, want %#x", gotMark, wantMark)
	}
	if !restored.IPTables().CheckPostrouting(out2, restoredRt, nil, "eth0") {
		t.Fatal("restored CheckPostrouting dropped existing flow packet")
	}
	if gotSrc := header.IPv4(out2.NetworkHeader().Slice()).SourceAddress(); gotSrc != snatAddr {
		t.Errorf("post-restore SNAT source = %s, want %s", gotSrc, snatAddr)
	}
	if gotPort := header.UDP(out2.TransportHeader().Slice()).SourcePort(); gotPort != snatPort {
		t.Errorf("post-restore SNAT port = %d, want %d", gotPort, snatPort)
	}
	out2.DecRef()
	if got := restored.ConntrackCount(); got != 1 {
		t.Fatalf("ConntrackCount after existing flow packet = %d, want 1", got)
	}

	// Verify a brand-new SNAT flow allocates a dynamic port via restored ct.rng.
	outNew := buildIPv4UDPPacket(fibAddr(10, 0, 0, 3), serverAddr, 42000, serverPort, []byte("new"))
	if !restored.IPTables().CheckOutput(outNew, restoredRt, "eth0") || !restored.IPTables().CheckPostrouting(outNew, restoredRt, nil, "eth0") {
		t.Fatal("new SNAT flow failed after restore")
	}
	outNew.DecRef()
	if got := restored.ConntrackCount(); got != 2 {
		t.Fatalf("ConntrackCount after second flow = %d, want 2", got)
	}

	// Advance restored clock past 300s stream timeout and sweep all reaper buckets.
	restoredClock := restored.Clock().(*faketime.ManualClock)
	restoredClock.Advance(305 * time.Second)
	for range 135 {
		restoredClock.Advance(5 * time.Second)
	}
	if got := restored.ConntrackCount(); got != 0 {
		t.Fatalf("ConntrackCount after expiry and full reaper sweep = %d, want 0 (never negative)", got)
	}
}

func TestPolicyRoutingAndNeighborGCSaveLoad(t *testing.T) {
	s := newFibStack(t)
	s.AddRoute(tcpip.Route{
		Destination: fibSubnet(t, 0, 0, 0, 0, 0),
		NIC:         fibWG0,
		RouteAttrs:  tcpip.RouteAttrs{Table: 100},
	})
	s.AddRoute(tcpip.Route{
		Destination: fibSubnet(t, 10, 42, 0, 0, 24),
		RouteAttrs:  tcpip.RouteAttrs{Type: tcpip.RouteTypeBlackhole},
	})
	rule := stack.PolicyRule{
		Priority:          100,
		Action:            stack.RuleActionToTable,
		Table:             100,
		Mark:              0x1,
		MarkMask:          0x1,
		SuppressPrefixLen: -1,
	}
	if err := s.AddRule(ipv4.ProtocolNumber, rule, stack.RuleInsert{Excl: true}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	wantGC := stack.NeighborGCThresholds{Thresh1: 64, Thresh2: 256, Thresh3: 512}
	if err := s.SetNeighborGCThresholds(ipv4.ProtocolNumber, wantGC); err != nil {
		t.Fatalf("SetNeighborGCThresholds: %v", err)
	}

	s.SetRemoveConf(true)
	ctx := context.Background()
	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &s); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	var restored *stack.Stack
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer restored.Close()

	replacement := newFibStack(t)
	restored.ReplaceConfig(replacement)
	restored.Restore()

	dst := fibAddr(8, 8, 8, 8)
	if got, err := outgoingNIC(t, restored, stack.RouteFlow{}, dst); err != nil || got != fibEth0 {
		t.Errorf("unmarked lookup after restore = (%d, %v), want NIC %d", got, err, fibEth0)
	}
	if got, err := outgoingNIC(t, restored, stack.RouteFlow{Mark: 0x1}, dst); err != nil || got != fibWG0 {
		t.Errorf("marked lookup after restore = (%d, %v), want NIC %d", got, err, fibWG0)
	}
	if _, err := outgoingNIC(t, restored, stack.RouteFlow{}, fibAddr(10, 42, 0, 5)); err == nil || err.String() != (&tcpip.ErrRouteBlackhole{}).String() {
		t.Errorf("blackhole lookup after restore = %v, want ErrRouteBlackhole", err)
	}
	gotGC, err := restored.NeighborGCThresholds(ipv4.ProtocolNumber)
	if err != nil || gotGC != wantGC {
		t.Errorf("restored NeighborGCThresholds = (%+v, %v), want (%+v, nil)", gotGC, err, wantGC)
	}
}
