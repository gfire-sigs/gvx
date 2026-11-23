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
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/checksum"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/pipe"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/icmp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

type natPacketFamily struct {
	name        string
	protocol    tcpip.NetworkProtocolNumber
	guest, peer tcpip.Address
}

func natPacketFamilies() [2]natPacketFamily {
	return [2]natPacketFamily{
		{"IPv4", header.IPv4ProtocolNumber, tcpip.AddrFrom4([4]byte{10, 0, 2, 15}), tcpip.AddrFrom4([4]byte{192, 0, 2, 1})},
		{"IPv6", header.IPv6ProtocolNumber, tcpip.AddrFrom16(netip.MustParseAddr("2001:db8::2").As16()), tcpip.AddrFrom16(netip.MustParseAddr("2001:db8:1::1").As16())},
	}
}

func newNATPacketTestStack(t *testing.T, f natPacketFamily, cfg NATConfig) (*stack.Stack, *NATForwarder) {
	t.Helper()
	cfg.DNSServers = []string{"192.0.2.53:53"}
	// gVisor's TCP dispatcher waits outside synctest's fake clock.
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6,
		},
	}
	s := stack.New(opts)
	nf := newNATForwarder(cfg)
	nf.stack = stack.New(opts)
	nf.guestStack = s
	t.Cleanup(func() {
		_ = nf.Close()
		s.Close()
	})
	guest, host := pipe.New("", "", 1500)
	if err := nf.rebindHostNIC(nf.hostLink(checksumOffloadEndpoint{host})); err != nil {
		t.Fatal(err)
	}
	if err := configureLoopbackNIC(s, LoopbackNICID); err != nil {
		t.Fatal(err)
	}
	if err := configureNATNIC(s, Eth0NICID, checksumOffloadEndpoint{guest}, checksumOffloadEndpoint{host}, nf); err != nil {
		t.Fatal(err)
	}
	forwarder := udp.NewForwarder(nf.stack, nf.handleUDP)
	nf.stack.SetNATRelayTransportHandler(udp.ProtocolNumber, forwarder.HandlePacket)
	if f.protocol == header.IPv6ProtocolNumber {
		addr := tcpip.ProtocolAddress{
			Protocol:          f.protocol,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: f.guest, PrefixLen: 64},
		}
		if err := s.AddProtocolAddress(Eth0NICID, addr, stack.AddressProperties{}); err != nil {
			t.Fatalf("add IPv6 address: %s", err)
		}
		s.SetRouteTable(append(s.GetRouteTable(), tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: Eth0NICID}))
	}
	return s, nf
}

func (f natPacketFamily) packet(src, dst tcpip.Address, proto tcpip.TransportProtocolNumber, data []byte, offset uint16, more bool) []byte {
	if f.protocol == header.IPv4ProtocolNumber {
		var flags uint8
		if more {
			flags = header.IPv4FlagMoreFragments
		}
		p := make([]byte, header.IPv4MinimumSize+len(data))
		ip := header.IPv4(p)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(p)), ID: 1, Flags: flags, FragmentOffset: offset,
			TTL: 64, Protocol: uint8(proto), SrcAddr: src, DstAddr: dst,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		copy(p[header.IPv4MinimumSize:], data)
		return p
	}

	var ext header.IPv6ExtHdrSerializer
	extra := 0
	if more || offset != 0 {
		ext = header.IPv6ExtHdrSerializer{&header.IPv6SerializableFragmentExtHdr{
			FragmentOffset: offset / 8, M: more, Identification: 1,
		}}
		extra = header.IPv6FragmentExtHdrLength
	}
	p := make([]byte, header.IPv6MinimumSize+extra+len(data))
	header.IPv6(p).Encode(&header.IPv6Fields{
		PayloadLength: uint16(extra + len(data)), TransportProtocol: proto,
		HopLimit: 64, SrcAddr: src, DstAddr: dst, ExtensionHeaders: ext,
	})
	copy(p[header.IPv6MinimumSize+extra:], data)
	return p
}

func (f natPacketFamily) send(t *testing.T, s *stack.Stack, nic tcpip.NICID, p []byte) {
	t.Helper()
	if err := s.WriteRawPacket(nic, f.protocol, buffer.MakeWithData(p)); err != nil {
		t.Fatalf("write packet on NIC %d: %s", nic, err)
	}
}

func natTestUDP(src, dst tcpip.Address, srcPort, dstPort uint16, payload string) []byte {
	p := make([]byte, header.UDPMinimumSize+len(payload))
	udp := header.UDP(p)
	udp.Encode(&header.UDPFields{SrcPort: srcPort, DstPort: dstPort, Length: uint16(len(p))})
	copy(p[header.UDPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(len(p)))
	if csum := ^checksum.Checksum(p, xsum); csum != 0 {
		udp.SetChecksum(csum)
	} else {
		udp.SetChecksum(0xffff)
	}
	return p
}

func (f natPacketFamily) echoFragments() (first, last []byte) {
	p := make([]byte, 24)
	binary.BigEndian.PutUint16(p[4:6], 1)
	proto := header.ICMPv4ProtocolNumber
	if f.protocol == header.IPv4ProtocolNumber {
		icmp := header.ICMPv4(p)
		icmp.SetType(header.ICMPv4Echo)
		icmp.SetChecksum(^checksum.Checksum(p, 0))
	} else {
		icmp := header.ICMPv6(p)
		icmp.SetType(header.ICMPv6EchoRequest)
		icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: f.guest, Dst: f.peer}))
		proto = header.ICMPv6ProtocolNumber
	}
	return f.packet(f.guest, f.peer, proto, p[:16], 0, true), f.packet(f.guest, f.peer, proto, p[16:], 16, false)
}

func (f natPacketFamily) echoCounters(guest, peer *stack.Stack) (request, timeExceeded *tcpip.StatCounter) {
	guestICMP, peerICMP := guest.Stats().ICMP, peer.Stats().ICMP
	if f.protocol == header.IPv4ProtocolNumber {
		return peerICMP.V4.PacketsReceived.EchoRequest, guestICMP.V4.PacketsReceived.TimeExceeded
	}
	return peerICMP.V6.PacketsReceived.EchoRequest, guestICMP.V6.PacketsReceived.TimeExceeded
}

func TestNATBandwidthChargesOriginalEchoFragmentLengths(t *testing.T) {
	for _, f := range natPacketFamilies() {
		t.Run(f.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				shaper := NewBandwidthShaper(BandwidthRates{})
				defer shaper.Close()
				s, nf := newNATPacketTestStack(t, f, NATConfig{Bandwidth: shaper})
				first, last := f.echoFragments()
				received, _ := f.echoCounters(s, nf.stack)
				f.send(t, s, Eth0NICID, last)
				// A retransmitted fragment must not add to the original L3 sum.
				f.send(t, s, Eth0NICID, last)
				shaper.SetRates(BandwidthRates{TXBPS: 8})
				f.send(t, s, Eth0NICID, first)
				want := time.Duration(len(first)+len(last)) * time.Second
				time.Sleep(want - time.Nanosecond)
				synctest.Wait()
				if got := received.Value(); got != 0 {
					t.Fatalf("NAT peer processed %d echo requests before paying for both original fragments", got)
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				if got := received.Value(); got != 1 {
					t.Fatalf("NAT peer processed %d echo requests after %v, want 1", got, want)
				}
			})
		})
	}
}

func TestNATBandwidthChargesRawUDPOutputAsAnIPPacket(t *testing.T) {
	for _, f := range natPacketFamilies() {
		t.Run(f.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				shaper := NewBandwidthShaper(BandwidthRates{})
				defer shaper.Close()
				s, nf := newNATPacketTestStack(t, f, NATConfig{Bandwidth: shaper})
				const peerPort, guestPort = 8000, 9000
				guest, err := gonet.DialUDP(s, &tcpip.FullAddress{Addr: f.guest, Port: guestPort}, nil, f.protocol)
				if err != nil {
					t.Fatal(err)
				}
				defer guest.Close()

				const body = "packet-only UDP"
				udp := natTestUDP(f.peer, f.guest, peerPort, guestPort, body)
				ip := f.packet(f.peer, f.guest, header.UDPProtocolNumber, udp, 0, false)
				shaper.SetRates(BandwidthRates{RXBPS: 8})
				start := time.Now()
				want := time.Duration(len(ip)) * time.Second
				if err := guest.SetReadDeadline(start.Add(want + time.Second)); err != nil {
					t.Fatal(err)
				}
				f.send(t, nf.stack, hostNICID, ip)
				var got [64]byte
				n, err := guest.Read(got[:])
				if err != nil || string(got[:n]) != body {
					t.Fatalf("guest read = (%q, %v), want %q", got[:n], err, body)
				}
				if elapsed := time.Since(start); elapsed != want {
					t.Fatalf("raw UDP arrived after %v, want %v for the whole IP packet", elapsed, want)
				}
			})
		})
	}
}

func TestNATBandwidthRelaysFragmentedUDPPayloadOnce(t *testing.T) {
	for _, f := range natPacketFamilies() {
		t.Run(f.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				shaper := NewBandwidthShaper(BandwidthRates{})
				defer shaper.Close()
				host, relay := net.Pipe()
				defer host.Close()
				defer relay.Close()
				s, _ := newNATPacketTestStack(t, f, NATConfig{
					Bandwidth: shaper,
					DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
						return relay, nil
					},
				})
				const body = "fragmented UDP payload"
				data := natTestUDP(f.guest, f.peer, 9000, 8000, body)
				proto := header.UDPProtocolNumber
				if f.protocol == header.IPv6ProtocolNumber {
					// Destination Options belong to the fragmentable payload.
					data = append([]byte{byte(proto), 0, 1, 4, 0, 0, 0, 0}, data...)
					proto = tcpip.TransportProtocolNumber(header.IPv6DestinationOptionsExtHdrIdentifier)
				}
				shaper.SetRates(BandwidthRates{TXBPS: 8})
				start := time.Now()
				want := time.Duration(len(body)) * time.Second
				if err := host.SetReadDeadline(start.Add(want + time.Second)); err != nil {
					t.Fatal(err)
				}
				f.send(t, s, Eth0NICID, f.packet(f.guest, f.peer, proto, data[16:], 16, false))
				f.send(t, s, Eth0NICID, f.packet(f.guest, f.peer, proto, data[:16], 0, true))
				var got [64]byte
				n, err := host.Read(got[:])
				if err != nil || string(got[:n]) != body {
					t.Fatalf("host read = (%q, %v), want %q", got[:n], err, body)
				}
				if elapsed := time.Since(start); elapsed != want {
					t.Fatalf("relayed UDP arrived after %v, want %v for payload only", elapsed, want)
				}
			})
		})
	}
}

func TestNATBandwidthPauseDiscardsPacketsFromPriorAttachmentEpoch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		shaper := NewBandwidthShaper(BandwidthRates{RXBPS: 8})
		defer shaper.Close()
		f := natPacketFamilies()[0]
		s, nf := newNATPacketTestStack(t, f, NATConfig{Bandwidth: shaper})
		const peerPort, guestPort = 8000, 9000
		guest, err := gonet.DialUDP(s, &tcpip.FullAddress{Addr: f.guest, Port: guestPort}, nil, f.protocol)
		if err != nil {
			t.Fatal(err)
		}
		defer guest.Close()
		send := func(data string) {
			p := natTestUDP(f.peer, f.guest, peerPort, guestPort, data)
			f.send(t, nf.stack, hostNICID, f.packet(f.peer, f.guest, header.UDPProtocolNumber, p, 0, false))
		}

		send("before pause")
		nf.QuiesceForSave()
		if err := nf.ResumeAfterSave(); err != nil {
			t.Fatal(err)
		}
		shaper.SetRates(BandwidthRates{})
		synctest.Wait()
		send("after resume")
		if err := guest.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var got [64]byte
		n, err := guest.Read(got[:])
		if err != nil || string(got[:n]) != "after resume" {
			t.Fatalf("guest read = (%q, %v), want only the new epoch's packet", got[:n], err)
		}
	})
}

func TestNATBandwidthPauseRetiresIncompleteReassembly(t *testing.T) {
	for _, f := range natPacketFamilies() {
		t.Run(f.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				shaper := NewBandwidthShaper(BandwidthRates{})
				defer shaper.Close()
				s, nf := newNATPacketTestStack(t, f, NATConfig{Bandwidth: shaper})
				first, last := f.echoFragments()
				echoes, timeouts := f.echoCounters(s, nf.stack)
				pause := func() {
					t.Helper()
					nf.QuiesceForSave()
					if err := nf.ResumeAfterSave(); err != nil {
						t.Fatal(err)
					}
				}

				f.send(t, s, Eth0NICID, first)
				pause()
				f.send(t, s, Eth0NICID, last)
				if got := echoes.Value(); got != 0 {
					t.Fatalf("NAT peer processed %d requests after combining fragments across pause, want none", got)
				}
				f.send(t, s, Eth0NICID, first)
				if got := echoes.Value(); got != 1 {
					t.Fatalf("NAT peer processed %d requests from a complete new assembly, want 1", got)
				}

				f.send(t, s, Eth0NICID, first)
				pause()
				time.Sleep(max(ipv4.ReassembleTimeout, ipv6.ReassembleTimeout) + time.Second)
				synctest.Wait()
				if got := timeouts.Value(); got != 0 {
					t.Fatalf("received %d fragment timeout replies from a retired epoch, want none", got)
				}
			})
		})
	}
}
