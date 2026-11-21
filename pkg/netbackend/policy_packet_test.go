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

package netbackend

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func TestPolicyPacketFromStackUDP(t *testing.T) {
	for _, tc := range []struct {
		name, local, remote string
		payload             int
		fragments           int
	}{
		{"IPv4 fragmented", "192.0.2.1/24", "192.0.2.2", 1500, 2},
		{"IPv6 unfragmented", "2001:db8:5::1/64", "2001:db8:5::2", 16, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := netip.MustParsePrefix(tc.local)
			remote := netip.MustParseAddr(tc.remote)
			s, ep := newTestStack(t, 1280, local)
			laddr, raddr := fullAddr(local.Addr(), 43210), fullAddr(remote, 53)
			conn, err := gonet.DialUDP(s, &laddr, &raddr, netProto(remote))
			if err != nil {
				t.Fatalf("dial in memory: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if n, err := conn.Write(make([]byte, tc.payload)); n != tc.payload || err != nil {
				t.Fatalf("write UDP payload = (%d, %v), want (%d, nil)", n, err, tc.payload)
			}
			for i := range tc.fragments {
				pkt := readPolicyTestUDP(t, ep, netProto(remote))
				tuple, ipBytes, socketBacked, ok := policyPacketDetails(pkt)
				if !ok || !socketBacked || ipBytes != pkt.Size() {
					t.Fatalf("UDP fragment %d: valid = %t, socket-backed = %t, IP bytes = %d, packet = %d", i, ok, socketBacked, ipBytes, pkt.Size())
				}
				if tuple.IPv6 != remote.Is6() || tuple.Source != local.Addr() || tuple.Destination != remote ||
					!tuple.ProtocolKnown || tuple.Protocol != uint8(header.UDPProtocolNumber) {
					t.Fatalf("UDP fragment %d: bad family, addresses, or protocol: %+v", i, tuple)
				}
				if i == 0 {
					if !tuple.SourcePortKnown || !tuple.DestinationPortKnown || tuple.SourcePort != 43210 || tuple.DestinationPort != 53 {
						t.Fatalf("first UDP fragment did not expose its ports: %+v", tuple)
					}
				} else if tuple.SourcePortKnown || tuple.DestinationPortKnown {
					t.Fatalf("non-initial UDP fragment exposed ports: %+v", tuple)
				}
			}
		})
	}
}

func readPolicyTestUDP(t *testing.T, ep *channel.Endpoint, proto tcpip.NetworkProtocolNumber) *stack.PacketBuffer {
	t.Helper()
	ctx := testContext(t)
	for {
		pkt := ep.ReadContext(ctx)
		if pkt == nil {
			t.Fatalf("read UDP packet: %v", ctx.Err())
		}
		if pkt.NetworkProtocolNumber == proto {
			h := pkt.NetworkHeader().Slice()
			if len(h) != 0 && policyTestProtocol(h, proto) == uint8(header.UDPProtocolNumber) {
				t.Cleanup(pkt.DecRef)
				return pkt
			}
		}
		pkt.DecRef()
	}
}

func policyTestProtocol(h []byte, proto tcpip.NetworkProtocolNumber) uint8 {
	if proto == header.IPv4ProtocolNumber {
		return header.IPv4(h).Protocol()
	}
	return header.IPv6(h).NextHeader()
}

func TestPolicyPacketFromStackRawWriter(t *testing.T) {
	s, ep := newTestStack(t, 1280)
	wire := policyTestIPv6Packet(uint8(header.IPv6NoNextHeaderIdentifier), nil)
	if err := s.WriteRawPacket(1, header.IPv6ProtocolNumber, buffer.MakeWithData(wire)); err != nil {
		t.Fatalf("write raw packet to channel NIC: %v", err)
	}
	ctx := testContext(t)
	for {
		pkt := ep.ReadContext(ctx)
		if pkt == nil {
			t.Fatalf("read raw packet: %v", ctx.Err())
		}
		if pkt.NetworkProtocolNumber != header.IPv6ProtocolNumber || len(pkt.NetworkHeader().Slice()) != 0 {
			pkt.DecRef()
			continue
		}
		tuple, ok := policyPacketTuple(pkt)
		pkt.DecRef()
		if !ok || !tuple.IPv6 || !tuple.ProtocolKnown || tuple.Protocol != uint8(header.IPv6NoNextHeaderIdentifier) {
			t.Fatalf("raw writer tuple = %+v, valid = %t", tuple, ok)
		}
		return
	}
}

func TestPolicyPacketIPv6WalksSplitViews(t *testing.T) {
	const hop = uint8(header.IPv6HopByHopOptionsExtHdrIdentifier)
	const dest = uint8(header.IPv6DestinationOptionsExtHdrIdentifier)
	const tcp = uint8(header.TCPProtocolNumber)
	tcpFields := make(header.TCP, header.TCPMinimumSize)
	tcpFields.Encode(&header.TCPFields{SrcPort: 12345, DstPort: 443, DataOffset: header.TCPMinimumSize})
	ext := []byte{dest, 0, 0, 0, 0, 0, 0, 0, tcp, 0, 0, 0, 0, 0, 0, 0}
	wire := policyTestIPv6Packet(hop, append(ext, tcpFields...))
	padded := append(bytes.Clone(wire), 0xff, 0xff)
	pkt := policyTestPacketBuffer(t, header.IPv6ProtocolNumber, padded[:5], padded[5:41], padded[41:57], padded[57:59], padded[59:])
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	tuple, ipBytes, socketBacked, ok := policyPacketDetails(pkt)
	if !ok || !socketBacked || ipBytes != len(wire) || !tuple.IPv6 || !tuple.ProtocolKnown || tuple.Protocol != tcp ||
		!tuple.SourcePortKnown || !tuple.DestinationPortKnown || tuple.SourcePort != 12345 || tuple.DestinationPort != 443 {
		t.Fatalf("split IPv6 packet: tuple = %+v, valid = %t, socket-backed = %t, IP bytes = %d, want %d", tuple, ok, socketBacked, ipBytes, len(wire))
	}
	view := pkt.ToView()
	defer view.Release()
	if !bytes.Equal(view.AsSlice(), padded) || pkt.HeaderSize() != 0 || pkt.Data().Size() != len(padded) {
		t.Fatal("tuple extraction modified bytes or consumed a packet header")
	}
}

func TestPolicyPacketIPv6FragmentsExposeOnlyValidatedFields(t *testing.T) {
	const dest = uint8(header.IPv6DestinationOptionsExtHdrIdentifier)
	const fragment = uint8(header.IPv6FragmentExtHdrIdentifier)
	const tcp = uint8(header.TCPProtocolNumber)
	const udp = uint8(header.UDPProtocolNumber)
	udpHeader := make(header.UDP, header.UDPMinimumSize)
	udpHeader.Encode(&header.UDPFields{SrcPort: 12345, DstPort: 53, Length: 16})
	for _, tc := range []struct {
		name       string
		next, want uint8
		field      uint16
		bytes      []byte
		known      bool
		portsKnown bool
	}{
		{name: "first UDP fragment permits full header", next: udp, want: udp, field: 1, bytes: udpHeader, known: true, portsKnown: true},
		{name: "first TCP fragment lacks full header", next: tcp, want: tcp, field: 1, bytes: make([]byte, 8), known: true},
		{name: "later fragment identifies direct protocol", next: udp, want: udp, field: 8, bytes: udpHeader, known: true},
		{name: "later fragment cannot reveal terminal protocol", next: dest, field: 8, bytes: udpHeader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frag := make([]byte, header.IPv6FragmentExtHdrLength)
			frag[0] = tc.next
			binary.BigEndian.PutUint16(frag[2:4], tc.field)
			wire := policyTestIPv6Packet(fragment, append(frag, tc.bytes...))
			tuple, ok := policyPacketTuple(policyTestPacketBuffer(t, header.IPv6ProtocolNumber, wire))
			if !ok || tuple.ProtocolKnown != tc.known || tuple.Protocol != tc.want ||
				tuple.SourcePortKnown != tc.portsKnown || tuple.DestinationPortKnown != tc.portsKnown {
				t.Fatalf("tuple = %+v, valid = %t, want known protocol = %t (%d), known ports = %t", tuple, ok, tc.known, tc.want, tc.portsKnown)
			}
			if tc.portsKnown && (tuple.SourcePort != 12345 || tuple.DestinationPort != 53) {
				t.Fatalf("UDP fragment ports = (%d, %d), want (12345, 53)", tuple.SourcePort, tuple.DestinationPort)
			}
		})
	}
}

func TestPolicyPacketAHIsPacketOnly(t *testing.T) {
	const ah = uint8(header.IPv6AuthenticationExtHdrIdentifier)
	const udp = uint8(header.UDPProtocolNumber)
	payload := make([]byte, 16+header.UDPMinimumSize)
	payload[0], payload[1] = udp, 2
	header.UDP(payload[16:]).Encode(&header.UDPFields{SrcPort: 12345, DstPort: 53, Length: header.UDPMinimumSize})
	wire := policyTestIPv6Packet(ah, payload)
	tuple, ipBytes, socketBacked, ok := policyPacketDetails(policyTestPacketBuffer(t, header.IPv6ProtocolNumber, wire))
	if !ok || socketBacked || ipBytes != len(wire) || !tuple.ProtocolKnown || tuple.Protocol != udp || tuple.DestinationPort != 53 {
		t.Fatalf("AH transport tuple = %+v, valid = %t, socket-backed = %t, IP bytes = %d, want %d", tuple, ok, socketBacked, ipBytes, len(wire))
	}
}

func TestPolicyPacketRejectsMalformedIPv6(t *testing.T) {
	const hop = uint8(header.IPv6HopByHopOptionsExtHdrIdentifier)
	const dest = uint8(header.IPv6DestinationOptionsExtHdrIdentifier)
	const fragment = uint8(header.IPv6FragmentExtHdrIdentifier)
	const none = uint8(header.IPv6NoNextHeaderIdentifier)
	const udp = uint8(header.UDPProtocolNumber)

	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"declared payload is truncated", policyTestIPv6Packet(udp, make([]byte, 8))[:header.IPv6MinimumSize+7]},
		{"extension exceeds payload", policyTestIPv6Packet(dest, []byte{none, 1, 0, 0, 0, 0, 0, 0})},
		{"option exceeds extension", policyTestIPv6Packet(hop, []byte{none, 0, 1, 5, 0, 0, 0, 0})},
		{"late hop-by-hop header", policyTestIPv6Packet(dest, []byte{hop, 0, 0, 0, 0, 0, 0, 0, none, 0, 0, 0, 0, 0, 0, 0})},
		{"second fragment header", policyTestIPv6Packet(fragment, []byte{fragment, 0, 0, 0, 0, 0, 0, 0, none, 0, 0, 0, 0, 0, 0, 0})},
		{"unaligned non-final fragment", policyTestIPv6Packet(fragment, []byte{udp, 0, 0, 1, 0, 0, 0, 0, 1})},
		{"bad UDP length", policyTestIPv6Packet(udp, []byte{0, 1, 0, 2, 0, 7, 0, 0})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tuple, ok := policyPacketTuple(policyTestPacketBuffer(t, header.IPv6ProtocolNumber, tc.wire)); ok {
				t.Fatalf("malformed packet yielded tuple %+v", tuple)
			}
		})
	}
}

func TestPolicyPacketIPv6HeaderWalkLimits(t *testing.T) {
	const dest = uint8(header.IPv6DestinationOptionsExtHdrIdentifier)
	const none = uint8(header.IPv6NoNextHeaderIdentifier)
	for _, tc := range []struct {
		name        string
		n, extBytes int
		valid       bool
	}{
		{"at header count limit", 8, 8, true},
		{"over header count limit", 9, 8, false},
		{"at byte limit", 1, 256, true},
		{"over byte limit", 1, 264, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.n*tc.extBytes)
			for i := range tc.n {
				payload[i*tc.extBytes], payload[i*tc.extBytes+1] = dest, uint8(tc.extBytes/8-1)
			}
			payload[len(payload)-tc.extBytes] = none
			wire := policyTestIPv6Packet(dest, payload)
			tuple, ok := policyPacketTuple(policyTestPacketBuffer(t, header.IPv6ProtocolNumber, wire))
			if ok != tc.valid || (ok && (!tuple.ProtocolKnown || tuple.Protocol != none)) {
				t.Fatalf("tuple = %+v, valid = %t, want valid = %t", tuple, ok, tc.valid)
			}
		})
	}
}

func TestPolicyPacketIPv4BoundsTransportByDeclaredLength(t *testing.T) {
	wire := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	h := header.IPv4(wire)
	h.Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize + 4, TTL: 64, Protocol: uint8(header.TCPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), DstAddr: tcpip.AddrFrom4([4]byte{192, 0, 2, 2}),
	})
	h.SetChecksum(^h.CalculateChecksum())
	header.TCP(wire[header.IPv4MinimumSize:]).Encode(&header.TCPFields{SrcPort: 101, DstPort: 443, DataOffset: header.TCPMinimumSize})
	if tuple, ok := policyPacketTuple(policyTestPacketBuffer(t, header.IPv4ProtocolNumber, wire)); ok {
		t.Fatalf("TCP bytes beyond declared IPv4 length produced tuple %+v", tuple)
	}
}

func policyTestIPv6Packet(next uint8, payload []byte) []byte {
	wire := make([]byte, header.IPv6MinimumSize, header.IPv6MinimumSize+len(payload))
	header.IPv6(wire).Encode(&header.IPv6Fields{
		PayloadLength: uint16(len(payload)), TransportProtocol: tcpip.TransportProtocolNumber(next), HopLimit: 64,
		SrcAddr: fullAddr(netip.MustParseAddr("2001:db8::1"), 0).Addr,
		DstAddr: fullAddr(netip.MustParseAddr("2001:db8::2"), 0).Addr,
	})
	return append(wire, payload...)
}

func policyTestPacketBuffer(t *testing.T, proto tcpip.NetworkProtocolNumber, views ...[]byte) *stack.PacketBuffer {
	t.Helper()
	var payload buffer.Buffer
	for _, view := range views {
		payload.Append(buffer.NewViewWithData(view))
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: payload})
	pkt.NetworkProtocolNumber = proto
	t.Cleanup(pkt.DecRef)
	return pkt
}
