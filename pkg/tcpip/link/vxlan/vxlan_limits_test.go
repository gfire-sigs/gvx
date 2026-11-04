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
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/checksum"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/link/ethernet"
	"z.gfire.dev/gvx/pkg/tcpip/link/pipe"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

func newTestStack(t *testing.T) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	t.Cleanup(func() {
		s.Close()
		s.Wait()
	})
	return s
}

func addAddr(t *testing.T, s *stack.Stack, nic tcpip.NICID, addr tcpip.Address, prefix int) {
	t.Helper()
	proto := ipv4.ProtocolNumber
	if addr.Len() == header.IPv6AddressSize {
		proto = ipv6.ProtocolNumber
	}
	pa := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: prefix}}
	if err := s.AddProtocolAddress(nic, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %v): %v", nic, addr, err)
	}
}

func mustSubnet(t *testing.T, addr tcpip.Address, ones int) tcpip.Subnet {
	t.Helper()
	sub, err := tcpip.NewSubnet(addr, tcpip.MaskFromBytes(prefixMask(addr.Len(), ones)))
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

func prefixMask(size, ones int) []byte {
	m := make([]byte, size)
	for i := range m {
		switch {
		case ones >= 8:
			m[i], ones = 0xff, ones-8
		case ones > 0:
			m[i], ones = byte(0xff<<(8-ones)), 0
		}
	}
	return m
}

// TestLinksThatRouteThroughEachOtherDropTheLoop sets up two links whose outer
// routes leave through each other, with neighbor and FDB entries that would
// carry a frame around forever. The first link drops the packet, so the second
// link sends nothing and the goroutine does not overflow its stack.
func TestLinksThatRouteThroughEachOtherDropTheLoop(t *testing.T) {
	s := newTestStack(t)
	mk := func(id tcpip.NICID, vni uint32, port uint16, overlay tcpip.Address) *Endpoint {
		ep, err := New(s, Config{ID: id, VNI: vni, Port: port})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := s.CreateNIC(id, ep); err != nil {
			t.Fatalf("CreateNIC: %v", err)
		}
		addAddr(t, s, id, overlay, 24)
		return ep
	}
	v1 := mk(1, 7, 4789, ip4(192, 168, 1, 1))
	v2 := mk(2, 8, 4790, ip4(192, 168, 2, 1))
	s.SetRouteTable([]tcpip.Route{
		{Destination: mustSubnet(t, ip4(192, 168, 1, 0), 24), NIC: 1},
		{Destination: mustSubnet(t, ip4(192, 168, 2, 0), 24), NIC: 2},
	})
	macA, macB, macC := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0a"), tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0b"), tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0c")
	// A frame for macA leaves v1 for 192.168.2.9, which routes through v2. v2
	// would send a frame for macB to 192.168.1.9, which routes through v1, and
	// so on.
	if err := s.AddStaticNeighbor(2, ipv4.ProtocolNumber, ip4(192, 168, 2, 9), macB); err != nil {
		t.Fatal(err)
	}
	if err := s.AddStaticNeighbor(1, ipv4.ProtocolNumber, ip4(192, 168, 1, 9), macC); err != nil {
		t.Fatal(err)
	}
	for _, e := range []struct {
		ep  *Endpoint
		mac tcpip.LinkAddress
		to  tcpip.Address
	}{{v1, macA, ip4(192, 168, 2, 9)}, {v1, macC, ip4(192, 168, 2, 9)}, {v2, macB, ip4(192, 168, 1, 9)}} {
		if err := e.ep.FDBUpdate(e.mac, NUDPermanent, NTFSelf, Remote{IP: e.to, Port: 4789, VNI: 7}, UpdateMode{Create: true}); err != nil {
			t.Fatal(err)
		}
	}
	frame := make([]byte, 60)
	copy(frame, macA)
	var pkts stack.PacketBufferList
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	defer pkt.DecRef()
	pkts.PushBack(pkt)
	if n, err := v1.WritePackets(pkts); n != 1 || err != nil {
		t.Fatalf("WritePackets = %d, %v; want 1, nil", n, err)
	}
	if got := s.NICInfo()[2].Stats.Tx.Packets.Value(); got != 0 {
		t.Fatalf("the second link sent %d packets, want 0 because the first link drops the loop", got)
	}
}

// singleNode returns a stack with one underlay NIC on a pipe with the MTU.
func singleNode(t *testing.T, pipeMTU uint32, addr tcpip.Address) *stack.Stack {
	t.Helper()
	s := newTestStack(t)
	p, _ := pipe.New("\x02\x00\x00\x00\x00\x01", "\x02\x00\x00\x00\x00\x02", pipeMTU)
	if err := s.CreateNIC(1, ethernet.New(p)); err != nil {
		t.Fatal(err)
	}
	addAddr(t, s, 1, addr, 24)
	return s
}

func TestMTUCapsAtTheLargestOuterPacket(t *testing.T) {
	// The pipe MTU includes the Ethernet header, so the NIC has 65536.
	s := singleNode(t, 65536+14, ip4(10, 0, 0, 1))
	if info, _ := s.SingleNICInfo(1); info.MTU != 65536 {
		t.Fatalf("underlay MTU = %d, want 65536", info.MTU)
	}
	ep, err := New(s, Config{ID: 2, VNI: 1, Link: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()
	if got, want := ep.MTU(), uint32(65535-Overhead4); got != want {
		t.Errorf("derived MTU on a 65536 underlay = %d, want %d", got, want)
	}
	cfg := Config{VNI: 2}
	if got, want := cfg.MaxMTU(), uint32(65535-Overhead4); got != want {
		t.Errorf("MaxMTU for IPv4 = %d, want %d", got, want)
	}
	cfg.Local = tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if got, want := cfg.MaxMTU(), uint32(65535-Overhead6); got != want {
		t.Errorf("MaxMTU for IPv6 = %d, want %d", got, want)
	}
	for _, mtu := range []uint32{MinMTU - 1, 65535 - Overhead4 + 1, 65535} {
		if _, err := New(s, Config{ID: 3, VNI: 3, MTU: mtu}); !errors.Is(err, ErrBadMTU) {
			t.Errorf("New with MTU %d = %v, want ErrBadMTU", mtu, err)
		}
	}
	for _, mtu := range []uint32{MinMTU, 1450, 65535 - Overhead4} {
		e, err := New(s, Config{ID: 3, VNI: uint32(10 + mtu%7), Port: uint16(5000 + mtu%1000), MTU: mtu})
		if err != nil {
			t.Errorf("New with MTU %d = %v, want success", mtu, err)
			continue
		}
		e.Close()
	}
}

func TestMTUOnTheUsualUnderlayIs1450(t *testing.T) {
	s := singleNode(t, 1514, ip4(10, 0, 0, 1))
	ep, err := New(s, Config{ID: 2, VNI: 1, Link: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()
	if ep.MTU() != 1450 {
		t.Errorf("MTU over a 1500 underlay = %d, want 1450", ep.MTU())
	}
}

func TestFDBLimit(t *testing.T) {
	var tb fdb
	now := time.Now()
	r := Remote{IP: ip4(10, 0, 0, 1)}
	mac := func(i int) tcpip.LinkAddress { return tcpip.LinkAddress([]byte{2, 0, 0, 0, byte(i >> 8), byte(i)}) }
	for i := range 3 {
		if err := tb.update(mac(i), NUDPermanent, 0, r, UpdateMode{Create: true}, now, 0, 3); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	if err := tb.update(mac(3), NUDPermanent, 0, r, UpdateMode{Create: true}, now, 0, 3); !errors.Is(err, ErrNoSpace) {
		t.Errorf("fourth static entry with limit 3 = %v, want ErrNoSpace", err)
	}
	if err := tb.update(mac(0), NUDPermanent, 0, Remote{IP: ip4(10, 0, 0, 2)}, UpdateMode{Create: true, Replace: true}, now, 0, 3); err != nil {
		t.Errorf("replace in a full table = %v, want success", err)
	}
	if !tb.learn(mac(9), r, 3, now, 0) {
		t.Error("learning in a full table dropped the frame")
	}
	if _, ok := tb.entries[mac(9)]; ok {
		t.Error("learning added an entry to a full table")
	}
}

func TestFDBHardLimit(t *testing.T) {
	var tb fdb
	now := time.Now()
	r := Remote{IP: ip4(10, 0, 0, 1)}
	mac := func(i int) tcpip.LinkAddress {
		return tcpip.LinkAddress([]byte{2, 0, 0, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	for i := range MaxFDBEntries {
		// A link limit above the hard limit has no effect.
		if err := tb.update(mac(i), NUDPermanent, 0, r, UpdateMode{Create: true}, now, 0, 1<<31); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	if err := tb.update(mac(MaxFDBEntries), NUDPermanent, 0, r, UpdateMode{Create: true}, now, 0, 0); !errors.Is(err, ErrNoSpace) {
		t.Errorf("entry %d = %v, want ErrNoSpace", MaxFDBEntries, err)
	}
}

func TestRemoteLimit(t *testing.T) {
	var tb fdb
	now := time.Now()
	for i := range MaxRemotes {
		r := Remote{IP: tcpip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})}
		if err := tb.update(zeroMAC, NUDPermanent, 0, r, UpdateMode{Create: true, Append: true}, now, 0, 0); err != nil {
			t.Fatalf("remote %d: %v", i, err)
		}
	}
	r := Remote{IP: tcpip.AddrFrom4([4]byte{10, 1, 0, 0})}
	if err := tb.update(zeroMAC, NUDPermanent, 0, r, UpdateMode{Create: true, Append: true}, now, 0, 0); !errors.Is(err, ErrNoSpace) {
		t.Errorf("remote %d = %v, want ErrNoSpace", MaxRemotes, err)
	}
}

func TestLearningSweepsExpiredEntriesBeforeItCountsTheLimit(t *testing.T) {
	var tb fdb
	now := time.Now()
	const ageing = 300 * time.Second
	old := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")
	tb.learn(old, Remote{IP: ip4(10, 0, 0, 1)}, 1, now, ageing)
	if tb.nextExpiry.IsZero() || tb.nextExpiry.After(now.Add(ageing)) {
		t.Fatalf("nextExpiry = %v, want at most %v", tb.nextExpiry, now.Add(ageing))
	}
	fresh := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	if !tb.learn(fresh, Remote{IP: ip4(10, 0, 0, 2)}, 1, now.Add(ageing+time.Second), ageing) {
		t.Fatal("learning dropped the frame")
	}
	if _, ok := tb.entries[old]; ok {
		t.Error("the expired entry survived the learn")
	}
	if _, ok := tb.entries[fresh]; !ok {
		t.Error("the table is full of expired entries, so learning must add the new one")
	}
}

func TestLookupScansOnlyWhenAnEntryIsDue(t *testing.T) {
	var tb fdb
	now := time.Now()
	const ageing = 300 * time.Second
	r := Remote{IP: ip4(10, 0, 0, 1)}
	for i := range 100 {
		tb.learn(tcpip.LinkAddress([]byte{2, 0, 0, 0, 0, byte(i)}), r, 0, now, ageing)
	}
	tb.mu.Lock()
	before := tb.nextExpiry
	tb.expiredLocked(now.Add(ageing-time.Second), ageing)
	if !tb.nextExpiry.Equal(before) || len(tb.entries) != 100 {
		t.Errorf("a call before the first expiry changed the table: %d entries, bound %v, want 100 entries and %v", len(tb.entries), tb.nextExpiry, before)
	}
	tb.expiredLocked(now.Add(ageing+time.Second), ageing)
	if len(tb.entries) != 0 || !tb.nextExpiry.IsZero() {
		t.Errorf("after the expiry: %d entries, bound %v, want none and no bound", len(tb.entries), tb.nextExpiry)
	}
	tb.mu.Unlock()
}

func BenchmarkLookup10kLearnedEntries(b *testing.B) {
	var tb fdb
	now := time.Now()
	const ageing = 300 * time.Second
	r := Remote{IP: ip4(10, 0, 0, 1)}
	for i := range 10000 {
		tb.learn(tcpip.LinkAddress([]byte{2, 0, 0, 0, byte(i >> 8), byte(i)}), r, 0, now, ageing)
	}
	key := tcpip.LinkAddress([]byte{2, 0, 0, 0, 0, 7})
	var scratch [4]Remote
	b.ResetTimer()
	for range b.N {
		tb.lookup(key, now, ageing, scratch[:0])
	}
}

func TestDuplicateVNIFailsForAnyLocalAddressOfTheFamilyAndPort(t *testing.T) {
	s := singleNode(t, 1514, ip4(10, 0, 0, 1))
	a, err := New(s, Config{ID: 2, VNI: 7, Port: 4789, Local: ip4(10, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := New(s, Config{ID: 3, VNI: 7, Port: 4789}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("a wildcard link with the VNI of a specific link = %v, want ErrDuplicate", err)
	}
	b, err := New(s, Config{ID: 3, VNI: 8, Port: 4789})
	if err != nil {
		t.Fatalf("a wildcard link with another VNI on the same port = %v, want success", err)
	}
	defer b.Close()
	if _, err := New(s, Config{ID: 4, VNI: 8, Port: 4789, Local: ip4(10, 0, 0, 1)}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("a specific link with the VNI of a wildcard link = %v, want ErrDuplicate", err)
	}
	// The same VNI on another port, and the same VNI in another stack, are fine.
	c, err := New(s, Config{ID: 4, VNI: 7, Port: 4790})
	if err != nil {
		t.Fatalf("the same VNI on another port = %v", err)
	}
	c.Close()
}

// TestIPv6UnderlayCarriesTheFrames sends frames over an IPv6 outer packet. The
// link has an IPv6 local address, so it binds an IPv6 UDP endpoint and its
// remotes are IPv6 addresses.
func TestIPv6UnderlayCarriesTheFrames(t *testing.T) {
	pa, pb := pipe.New("\x02\x00\x00\x00\x00\x01", "\x02\x00\x00\x00\x00\x02", 1514)
	ip6 := func(last byte) tcpip.Address {
		return tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last})
	}
	mk := func(p *pipe.Endpoint, under, over tcpip.Address) *node {
		s := newTestStack(t)
		if err := s.CreateNIC(underlayNIC, ethernet.New(p)); err != nil {
			t.Fatal(err)
		}
		addAddr(t, s, underlayNIC, under, 64)
		ep, err := New(s, Config{ID: overlayNIC, VNI: 7, Port: 4789, Local: under})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := s.CreateNIC(overlayNIC, ep); err != nil {
			t.Fatal(err)
		}
		addAddr(t, s, overlayNIC, over, 24)
		s.SetRouteTable([]tcpip.Route{
			{Destination: mustSubnet(t, ip6(0), 64), NIC: underlayNIC},
			{Destination: mustSubnet(t, ip4(192, 168, 1, 0), 24), NIC: overlayNIC},
		})
		return &node{stack: s, vxlan: ep, underlay: under, overlay: over}
	}
	a, b := mk(pa, ip6(1), ip4(192, 168, 1, 1)), mk(pb, ip6(2), ip4(192, 168, 1, 2))
	if cfg := a.vxlan.Config(); !cfg.IPv6() {
		t.Fatal("a link with an IPv6 local address is not an IPv6 link")
	}
	connect(t, a, b)
	if !echo(t, a, b, 9000, "six", 5*time.Second) {
		t.Fatal("datagram did not cross an IPv6 underlay")
	}
	// An IPv4 remote on an IPv6 link is refused.
	err := a.vxlan.FDBUpdate("\x02\x00\x00\x00\x00\x55", NUDPermanent, NTFSelf, Remote{IP: ip4(10, 0, 0, 1)}, UpdateMode{Create: true})
	if !errors.Is(err, ErrBadAddress) {
		t.Errorf("an IPv4 remote on an IPv6 link = %v, want ErrBadAddress", err)
	}
}

// outerPacket sends one frame through a link whose underlay is a channel
// endpoint, and returns the outer UDP header and the whole outer packet.
func outerPacket(t *testing.T, cfg Config) (header.UDP, []byte) {
	t.Helper()
	s := newTestStack(t)
	ch := channel.New(8, 1514, "\x02\x00\x00\x00\x00\x01")
	if err := s.CreateNIC(underlayNIC, ethernet.New(ch)); err != nil {
		t.Fatal(err)
	}
	addAddr(t, s, underlayNIC, ip4(10, 0, 0, 1), 24)
	if err := s.AddStaticNeighbor(underlayNIC, ipv4.ProtocolNumber, ip4(10, 0, 0, 2), "\x02\x00\x00\x00\x00\x02"); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: mustSubnet(t, ip4(10, 0, 0, 0), 24), NIC: underlayNIC}})
	cfg.ID = overlayNIC
	cfg.VNI, cfg.Port = 7, 4789
	ep, err := New(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()
	mac := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0a")
	if err := ep.FDBUpdate(mac, NUDPermanent, NTFSelf, Remote{IP: ip4(10, 0, 0, 2), Port: 4789, VNI: 7}, UpdateMode{Create: true}); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 60)
	copy(frame, mac)
	var pkts stack.PacketBufferList
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	defer pkt.DecRef()
	pkts.PushBack(pkt)
	ep.WritePackets(pkts)
	out := ch.Read()
	if out == nil {
		t.Fatal("the link sent no outer packet")
	}
	defer out.DecRef()
	v := out.ToView()
	defer v.Release()
	b := append([]byte(nil), v.AsSlice()...)
	ip := header.IPv4(b[header.EthernetMinimumSize:])
	if ip.TransportProtocol() != header.UDPProtocolNumber || ip.DestinationAddress() != ip4(10, 0, 0, 2) {
		t.Fatalf("outer packet = protocol %d to %v, want UDP to 10.0.0.2", ip.TransportProtocol(), ip.DestinationAddress())
	}
	return header.UDP(ip.Payload()), b[header.EthernetMinimumSize:]
}

func TestUDPChecksumDefaultsToOff(t *testing.T) {
	udpHdr, _ := outerPacket(t, Config{})
	if udpHdr.Checksum() != 0 {
		t.Errorf("outer checksum = %#x, want 0 without udpcsum", udpHdr.Checksum())
	}
	if udpHdr.DestinationPort() != 4789 {
		t.Errorf("outer destination port = %d, want 4789", udpHdr.DestinationPort())
	}
}

func TestUDPChecksumWhenRequested(t *testing.T) {
	udpHdr, ipPacket := outerPacket(t, Config{UDPCsum: true})
	ip := header.IPv4(ipPacket)
	if udpHdr.Checksum() == 0 {
		t.Fatal("outer checksum is 0 with udpcsum")
	}
	length := uint16(len(udpHdr))
	sum := checksum.Combine(header.PseudoHeaderChecksum(header.UDPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), length), checksum.Checksum(udpHdr, 0))
	if sum != 0xffff {
		t.Errorf("the outer checksum does not verify: sum = %#x, want 0xffff", sum)
	}
	if got := binary.BigEndian.Uint16(udpHdr[4:]); got != length {
		t.Errorf("UDP length = %d, want %d", got, length)
	}
}

// TestOuterSourcePortIsInTheRange checks the outer source port of real
// packets against the range of the link.
func TestOuterSourcePortIsInTheRange(t *testing.T) {
	udpHdr, _ := outerPacket(t, Config{PortLow: 41000, PortHigh: 41009})
	if p := udpHdr.SourcePort(); p < 41000 || p > 41009 {
		t.Errorf("outer source port = %d, want 41000 to 41009", p)
	}
}
