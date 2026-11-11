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

package wgtun

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/checksum"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/icmp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

const (
	testNICID   tcpip.NICID = 1
	testMTU     uint32      = 1420
	testTUNName             = "wg-test0"
	testTimeout             = 5 * time.Second
)

var (
	testLocalV4  = netip.MustParseAddr("10.9.0.1")
	testRemoteV4 = netip.MustParseAddr("10.9.0.2")
	testLocalV6  = netip.MustParseAddr("fd00:9::1")
	testRemoteV6 = netip.MustParseAddr("fd00:9::2")
)

func newTestDevice(t *testing.T) (*Device, *stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	ep := channel.New(DefaultQueueSize, testMTU, "")
	if err := s.CreateNIC(testNICID, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	v4 := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(testLocalV4.As4()),
			PrefixLen: 24,
		},
	}
	if err := s.AddProtocolAddress(testNICID, v4, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress v4: %v", err)
	}
	v6 := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16(testLocalV6.As16()),
			PrefixLen: 64,
		},
	}
	if err := s.AddProtocolAddress(testNICID, v6, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress v6: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: testNICID},
		{Destination: header.IPv6EmptySubnet, NIC: testNICID},
	})
	dev := New(ep, testTUNName)
	t.Cleanup(func() {
		_ = dev.Close()
		s.Close()
		s.Wait()
		ep.Close()
	})
	return dev, s, ep
}

func buildEchoRequestV4(src, dst netip.Addr, payload []byte) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	icmpHdr := header.ICMPv4(pkt[header.IPv4MinimumSize:])
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(7)
	icmpHdr.SetSequence(1)
	copy(icmpHdr.Payload(), payload)
	icmpHdr.SetChecksum(^checksum.Checksum(icmpHdr, 0))
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return pkt
}

func buildEchoRequestV6(src, dst netip.Addr, payload []byte) []byte {
	pkt := make([]byte, header.IPv6MinimumSize+header.ICMPv6EchoMinimumSize+len(payload))
	icmpHdr := header.ICMPv6(pkt[header.IPv6MinimumSize:])
	icmpHdr.SetType(header.ICMPv6EchoRequest)
	icmpHdr.SetIdent(7)
	icmpHdr.SetSequence(1)
	copy(icmpHdr.Payload(), payload)
	srcA, dstA := tcpip.AddrFrom16(src.As16()), tcpip.AddrFrom16(dst.As16())
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr[:header.ICMPv6EchoMinimumSize],
		Src:         srcA,
		Dst:         dstA,
		PayloadCsum: checksum.Checksum(icmpHdr.Payload(), 0),
		PayloadLen:  len(icmpHdr.Payload()),
	}))
	ip := header.IPv6(pkt)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(pkt) - header.IPv6MinimumSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcA,
		DstAddr:           dstA,
	})
	return pkt
}

func readBatch(t *testing.T, dev *Device, batch, offset int) [][]byte {
	t.Helper()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, offset+2048)
	}
	sizes := make([]int, batch)
	n, err := dev.Read(bufs, sizes, offset)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	out := make([][]byte, n)
	for i := range out {
		out[i] = bytes.Clone(bufs[i][offset : offset+sizes[i]])
	}
	return out
}

func TestDeviceMetadataAndNotifyMTU(t *testing.T) {
	dev, _, ep := newTestDevice(t)
	if dev.Endpoint() != ep {
		t.Fatalf("Endpoint() = %p, want %p", dev.Endpoint(), ep)
	}
	if dev.File() != nil {
		t.Fatalf("File() = %v, want nil", dev.File())
	}
	if mtu, err := dev.MTU(); err != nil || mtu != int(testMTU) {
		t.Fatalf("MTU() = (%d, %v), want (%d, nil)", mtu, err, testMTU)
	}
	if name, err := dev.Name(); err != nil || name != testTUNName {
		t.Fatalf("Name() = (%q, %v), want (%q, nil)", name, err, testTUNName)
	}
	if dev.BatchSize() != BatchSize {
		t.Fatalf("BatchSize() = %d, want %d", dev.BatchSize(), BatchSize)
	}
	select {
	case ev, ok := <-dev.Events():
		t.Fatalf("Events() delivered (%v, %v) before NotifyMTU, want no event", ev, ok)
	default:
	}

	dev.NotifyMTU()
	dev.NotifyMTU()
	select {
	case ev := <-dev.Events():
		if ev != tun.EventMTUUpdate {
			t.Fatalf("Events() = %v, want EventMTUUpdate", ev)
		}
	default:
		t.Fatal("NotifyMTU did not queue an MTU event")
	}
	select {
	case ev := <-dev.Events():
		t.Fatalf("second NotifyMTU queued duplicate event %v", ev)
	default:
	}
}

func TestDeviceReadReturnsOutboundPacketsAndBatches(t *testing.T) {
	dev, s, _ := newTestDevice(t)
	c, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{Addr: tcpip.AddrFrom4(testRemoteV4.As4()), Port: 9}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()

	const offset = 16
	payload := []byte("outbound-datagram")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	bufs := [][]byte{bytes.Repeat([]byte{0xAA}, offset+2048)}
	sizes := make([]int, 1)
	n, err := dev.Read(bufs, sizes, offset)
	if err != nil || n != 1 {
		t.Fatalf("Read = (%d, %v), want (1, nil)", n, err)
	}
	if !bytes.Equal(bufs[0][:offset], bytes.Repeat([]byte{0xAA}, offset)) {
		t.Fatal("Read overwrote bytes before offset")
	}
	pkt := bufs[0][offset : offset+sizes[0]]
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) || ip.DestinationAddress() != tcpip.AddrFrom4(testRemoteV4.As4()) ||
		ip.TransportProtocol() != header.UDPProtocolNumber {
		t.Fatalf("Read returned unexpected packet: %x", pkt)
	}
	if got := header.UDP(ip.Payload()).Payload(); !bytes.Equal(got, payload) {
		t.Fatalf("UDP payload = %q, want %q", got, payload)
	}

	const total = 5
	for i := range total {
		if _, err := c.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	first := readBatch(t, dev, 3, 0)
	second := readBatch(t, dev, 3, 0)
	if len(first) != 3 || len(second) != 2 {
		t.Fatalf("batch sizes = (%d, %d), want (3, 2)", len(first), len(second))
	}
	for i, p := range append(first, second...) {
		if got := header.UDP(header.IPv4(p).Payload()).Payload(); !bytes.Equal(got, []byte{byte(i)}) {
			t.Fatalf("packet %d payload = %x, want %x", i, got, []byte{byte(i)})
		}
	}
}

func TestDeviceReadDropsOversizedPackets(t *testing.T) {
	dev, s, _ := newTestDevice(t)
	c, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{Addr: tcpip.AddrFrom4(testRemoteV4.As4()), Port: 9}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()

	if _, err := c.Write(bytes.Repeat([]byte{1}, 600)); err != nil {
		t.Fatalf("Write big: %v", err)
	}
	if _, err := c.Write([]byte("small")); err != nil {
		t.Fatalf("Write small: %v", err)
	}
	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	n, err := dev.Read(bufs, sizes, 0)
	if err != nil || n != 1 {
		t.Fatalf("Read = (%d, %v), want (1, nil)", n, err)
	}
	if got := header.UDP(header.IPv4(bufs[0][:sizes[0]]).Payload()).Payload(); string(got) != "small" {
		t.Fatalf("Read returned payload %q, want \"small\"", got)
	}
}

func TestDeviceWriteInjectsIPv4AndIPv6AndValidatesPackets(t *testing.T) {
	dev, _, _ := newTestDevice(t)
	const offset = 16

	req4 := buildEchoRequestV4(testRemoteV4, testLocalV4, []byte("v4-ping"))
	buf4 := append(bytes.Repeat([]byte{0xEE}, offset), req4...)
	if n, err := dev.Write([][]byte{buf4}, offset); err != nil || n != 1 {
		t.Fatalf("Write v4 = (%d, %v), want (1, nil)", n, err)
	}
	reply4 := readBatch(t, dev, 1, 0)[0]
	if icmpHdr := header.ICMPv4(header.IPv4(reply4).Payload()); icmpHdr.Type() != header.ICMPv4EchoReply || !bytes.Equal(icmpHdr.Payload(), []byte("v4-ping")) {
		t.Fatalf("ICMPv4 reply = %x, want echo reply", reply4)
	}

	req6 := buildEchoRequestV6(testRemoteV6, testLocalV6, []byte("v6-ping"))
	buf6 := append(bytes.Repeat([]byte{0xEE}, offset), req6...)
	if n, err := dev.Write([][]byte{buf6}, offset); err != nil || n != 1 {
		t.Fatalf("Write v6 = (%d, %v), want (1, nil)", n, err)
	}
	reply6 := readBatch(t, dev, 1, 0)[0]
	if icmpHdr := header.ICMPv6(header.IPv6(reply6).Payload()); icmpHdr.Type() != header.ICMPv6EchoReply || !bytes.Equal(icmpHdr.Payload(), []byte("v6-ping")) {
		t.Fatalf("ICMPv6 reply = %x, want echo reply", reply6)
	}

	bad := [][]byte{
		nil,
		{0x45},
		{0x60, 0x01, 0x02},
		append([]byte{0x75}, make([]byte, 40)...),
	}
	for i, b := range bad {
		if n, err := dev.Write([][]byte{b}, 0); n != 0 || !errors.Is(err, ErrInvalidIPPacket) {
			t.Fatalf("Write(bad[%d]) = (%d, %v), want (0, ErrInvalidIPPacket)", i, n, err)
		}
	}
	if n, err := dev.Write([][]byte{bad[1], req4}, 0); n != 1 || !errors.Is(err, ErrInvalidIPPacket) {
		t.Fatalf("Write(mixed) = (%d, %v), want (1, ErrInvalidIPPacket)", n, err)
	}
	_ = readBatch(t, dev, 1, 0)
	if n, err := dev.Write([][]byte{req4}, len(req4)+1); err == nil || n != 0 {
		t.Fatalf("Write with excessive offset = (%d, %v), want error", n, err)
	}
}

func TestDeviceCloseAndValidationErrors(t *testing.T) {
	dev, _, ep := newTestDevice(t)
	if _, err := dev.Read([][]byte{make([]byte, 64), make([]byte, 64)}, make([]int, 1), 0); err == nil {
		t.Fatal("Read with short sizes succeeded, want error")
	}
	if _, err := dev.Read(nil, nil, 0); err == nil {
		t.Fatal("Read with nil bufs succeeded, want error")
	}

	readErr := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := dev.Read([][]byte{make([]byte, 2048)}, make([]int, 1), 0)
		readErr <- err
	}()
	<-started
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("blocked Read returned %v, want os.ErrClosed", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Read stayed blocked after Close")
	}
	if _, ok := <-dev.Events(); ok {
		t.Fatal("Events() channel remained open after Close")
	}
	dev.NotifyMTU()
	if err := dev.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := dev.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after Close = %v, want os.ErrClosed", err)
	}
	req4 := buildEchoRequestV4(testRemoteV4, testLocalV4, nil)
	if _, err := dev.Write([][]byte{req4}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close = %v, want os.ErrClosed", err)
	}

	dev2 := New(ep, "wg-test1")
	defer dev2.Close()
	ep.Close()
	if _, err := dev2.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read on closed endpoint = %v, want os.ErrClosed", err)
	}
}

func TestParseEndpointAndNewEndpoint(t *testing.T) {
	good := map[string]string{
		"192.0.2.1:51820":      "192.0.2.1:51820",
		"[2001:db8::1]:51820":  "[2001:db8::1]:51820",
		"[::ffff:192.0.2.1]:7": "192.0.2.1:7",
	}
	for in, want := range good {
		ep, err := ParseEndpoint(in)
		if err != nil {
			t.Fatalf("ParseEndpoint(%q): %v", in, err)
		}
		if got := ep.DstToString(); got != want {
			t.Fatalf("ParseEndpoint(%q).DstToString() = %q, want %q", in, got, want)
		}
		if ip := ep.DstIP(); ip.Is4In6() {
			t.Fatalf("ParseEndpoint(%q).DstIP() = %s, want unmapped IP", in, ip)
		}
	}
	for _, in := range []string{"", "example.com:51820", "192.0.2.1", "192.0.2.1:99999", "[::1]"} {
		if _, err := ParseEndpoint(in); err == nil {
			t.Fatalf("ParseEndpoint(%q) succeeded, want error", in)
		}
	}
}
