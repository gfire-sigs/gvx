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

package netfilter

import (
	"net/netip"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	nicLoopback tcpip.NICID = 1
	nicEth0     tcpip.NICID = 2
	nicBridge   tcpip.NICID = 3
)

// newAddrtypeStack builds a stack with a loopback NIC "lo", an "eth0" NIC
// and a "docker0" NIC. Each NIC holds IPv4 and IPv6 addresses.
func newAddrtypeStack(t *testing.T) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
	})
	t.Cleanup(s.Close)

	nics := []struct {
		id    tcpip.NICID
		name  string
		ep    stack.LinkEndpoint
		addrs []string
	}{
		{nicLoopback, "lo", loopback.New(), []string{"127.0.0.1/8", "::1/128"}},
		{nicEth0, "eth0", channel.New(1, 1500, ""), []string{"10.0.2.15/24", "fd00::2/64"}},
		{nicBridge, "docker0", channel.New(1, 1500, ""), []string{"172.17.0.1/16"}},
	}
	for _, n := range nics {
		if err := s.CreateNICWithOptions(n.id, n.ep, stack.NICOptions{Name: n.name}); err != nil {
			t.Fatalf("CreateNIC(%s): %v", n.name, err)
		}
		for _, a := range n.addrs {
			prefix := netip.MustParsePrefix(a)
			pa := tcpip.ProtocolAddress{AddressWithPrefix: tcpip.AddressWithPrefix{PrefixLen: prefix.Bits()}}
			if prefix.Addr().Is4() {
				pa.Protocol = ipv4.ProtocolNumber
				pa.AddressWithPrefix.Address = tcpip.AddrFrom4(prefix.Addr().As4())
			} else {
				pa.Protocol = ipv6.ProtocolNumber
				pa.AddressWithPrefix.Address = tcpip.AddrFrom16(prefix.Addr().As16())
			}
			if err := s.AddProtocolAddress(n.id, pa, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%s): %v", a, err)
			}
		}
	}
	return s
}

func addr4(s string) tcpip.Address { return tcpip.AddrFrom4(netip.MustParseAddr(s).As4()) }

func addr6(s string) tcpip.Address { return tcpip.AddrFrom16(netip.MustParseAddr(s).As16()) }

func TestClassifyIPv4(t *testing.T) {
	s := newAddrtypeStack(t)
	r := stackResolver{stk: s}
	tests := []struct {
		name  string
		addr  string
		nicID tcpip.NICID
		want  uint16
	}{
		{"assigned address", "10.0.2.15", 0, linux.XT_ADDRTYPE_LOCAL},
		{"assigned address on bridge", "172.17.0.1", 0, linux.XT_ADDRTYPE_LOCAL},
		{"loopback address", "127.0.0.1", 0, linux.XT_ADDRTYPE_LOCAL},
		{"loopback range", "127.5.6.7", 0, linux.XT_ADDRTYPE_LOCAL},
		{"remote address", "93.184.216.34", 0, linux.XT_ADDRTYPE_UNICAST},
		{"neighbor in local subnet", "10.0.2.2", 0, linux.XT_ADDRTYPE_UNICAST},
		{"limited broadcast", "255.255.255.255", 0, linux.XT_ADDRTYPE_BROADCAST},
		{"zero network", "0.0.0.0", 0, linux.XT_ADDRTYPE_BROADCAST},
		{"subnet broadcast", "10.0.2.255", 0, linux.XT_ADDRTYPE_BROADCAST},
		{"multicast", "224.0.0.251", 0, linux.XT_ADDRTYPE_MULTICAST},
		{"assigned address on its own NIC", "10.0.2.15", nicEth0, linux.XT_ADDRTYPE_LOCAL},
		{"assigned address on another NIC", "10.0.2.15", nicBridge, linux.XT_ADDRTYPE_UNICAST},
		{"loopback address on lo", "127.0.0.1", nicLoopback, linux.XT_ADDRTYPE_LOCAL},
		{"loopback address on eth0", "127.0.0.1", nicEth0, linux.XT_ADDRTYPE_UNICAST},
		{"subnet broadcast on its own NIC", "172.17.255.255", nicBridge, linux.XT_ADDRTYPE_BROADCAST},
		{"subnet broadcast on another NIC", "172.17.255.255", nicEth0, linux.XT_ADDRTYPE_UNICAST},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyAddress(r, header.IPv4ProtocolNumber, addr4(tc.addr), tc.nicID); got != tc.want {
				t.Errorf("classifyAddress(%s, nic %d) = 0x%x, want 0x%x", tc.addr, tc.nicID, got, tc.want)
			}
		})
	}
}

func TestClassifyIPv6(t *testing.T) {
	s := newAddrtypeStack(t)
	r := stackResolver{stk: s}
	tests := []struct {
		name  string
		addr  string
		nicID tcpip.NICID
		want  uint16
	}{
		{"unspecified", "::", 0, linux.XT_ADDRTYPE_UNSPEC},
		{"loopback", "::1", 0, linux.XT_ADDRTYPE_LOCAL},
		{"loopback on eth0", "::1", nicEth0, linux.XT_ADDRTYPE_UNICAST},
		{"assigned address", "fd00::2", 0, linux.XT_ADDRTYPE_LOCAL},
		{"assigned address on another NIC", "fd00::2", nicBridge, linux.XT_ADDRTYPE_UNICAST},
		{"remote address", "2606:2800:220:1::1", 0, linux.XT_ADDRTYPE_UNICAST},
		{"multicast", "ff02::1", 0, linux.XT_ADDRTYPE_MULTICAST},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyAddress(r, header.IPv6ProtocolNumber, addr6(tc.addr), tc.nicID); got != tc.want {
				t.Errorf("classifyAddress(%s, nic %d) = 0x%x, want 0x%x", tc.addr, tc.nicID, got, tc.want)
			}
		})
	}
}

func newIPv4Packet(t *testing.T, src, dst string) *stack.PacketBuffer {
	t.Helper()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.IPv4MinimumSize})
	t.Cleanup(pkt.DecRef)
	hdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	hdr.Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize,
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     addr4(src),
		DstAddr:     addr4(dst),
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	return pkt
}

func newIPv6Packet(t *testing.T, src, dst string) *stack.PacketBuffer {
	t.Helper()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.IPv6MinimumSize})
	t.Cleanup(pkt.DecRef)
	hdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	hdr.Encode(&header.IPv6Fields{
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           addr6(src),
		DstAddr:           addr6(dst),
	})
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
	return pkt
}

func TestAddrtypeMatch(t *testing.T) {
	s := newAddrtypeStack(t)
	const (
		local     = linux.XT_ADDRTYPE_LOCAL
		unicast   = linux.XT_ADDRTYPE_UNICAST
		multicast = linux.XT_ADDRTYPE_MULTICAST
	)
	tests := []struct {
		name     string
		matcher  AddrtypeMatcher
		src, dst string
		in, out  string
		want     bool
	}{
		// The rule that dockerd installs in the nat table.
		{"dst LOCAL, local destination", AddrtypeMatcher{dest: local}, "10.0.2.2", "10.0.2.15", "eth0", "", true},
		{"dst LOCAL, remote destination", AddrtypeMatcher{dest: local}, "10.0.2.2", "1.1.1.1", "eth0", "", false},
		{"dst LOCAL, loopback destination", AddrtypeMatcher{dest: local}, "127.0.0.1", "127.0.0.1", "lo", "", true},
		{"dst LOCAL inverted, remote destination", AddrtypeMatcher{dest: local, invertDest: true}, "10.0.2.2", "1.1.1.1", "", "eth0", true},
		{"dst LOCAL inverted, local destination", AddrtypeMatcher{dest: local, invertDest: true}, "10.0.2.2", "10.0.2.15", "", "eth0", false},
		{"src LOCAL", AddrtypeMatcher{source: local}, "172.17.0.1", "1.1.1.1", "", "eth0", true},
		{"src LOCAL, remote source", AddrtypeMatcher{source: local}, "172.17.0.2", "1.1.1.1", "", "eth0", false},
		{"mask with several types", AddrtypeMatcher{dest: local | multicast}, "10.0.2.2", "224.0.0.1", "eth0", "", true},
		{"mask UNICAST", AddrtypeMatcher{dest: unicast}, "10.0.2.2", "1.1.1.1", "eth0", "", true},
		{"both addresses must match", AddrtypeMatcher{source: unicast, dest: local}, "10.0.2.2", "1.1.1.1", "eth0", "", false},
		{"empty masks match all", AddrtypeMatcher{}, "10.0.2.2", "1.1.1.1", "eth0", "", true},
		{"inverted empty mask is ignored", AddrtypeMatcher{invertDest: true}, "10.0.2.2", "1.1.1.1", "eth0", "", true},
		// Interface limits.
		{"limit in, address on input NIC", AddrtypeMatcher{rev: 1, dest: local, limitIfaceIn: true}, "10.0.2.2", "10.0.2.15", "eth0", "", true},
		{"limit in, address on another NIC", AddrtypeMatcher{rev: 1, dest: local, limitIfaceIn: true}, "10.0.2.2", "172.17.0.1", "eth0", "", false},
		{"limit out, address on output NIC", AddrtypeMatcher{rev: 1, source: local, limitIfaceOut: true}, "172.17.0.1", "1.1.1.1", "", "docker0", true},
		{"limit out, address on another NIC", AddrtypeMatcher{rev: 1, source: local, limitIfaceOut: true}, "10.0.2.15", "1.1.1.1", "", "docker0", false},
		{"limit in, unknown NIC name removes the limit", AddrtypeMatcher{rev: 1, dest: local, limitIfaceIn: true}, "10.0.2.2", "172.17.0.1", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.matcher
			m.bindStack(s)
			pkt := newIPv4Packet(t, tc.src, tc.dst)
			got, hotdrop := m.Match(stack.Prerouting, pkt, tc.in, tc.out)
			if hotdrop {
				t.Fatalf("Match requested a hot drop")
			}
			if got != tc.want {
				t.Errorf("Match = %t, want %t", got, tc.want)
			}
		})
	}

	t.Run("IPv6 destination", func(t *testing.T) {
		m := AddrtypeMatcher{rev: 1, dest: local}
		m.bindStack(s)
		if got, _ := m.Match(stack.Prerouting, newIPv6Packet(t, "fd00::99", "fd00::2"), "eth0", ""); !got {
			t.Errorf("local IPv6 destination did not match")
		}
		if got, _ := m.Match(stack.Prerouting, newIPv6Packet(t, "fd00::99", "fd00::98"), "eth0", ""); got {
			t.Errorf("remote IPv6 destination matched")
		}
	})

	t.Run("unbound matcher treats all addresses as UNICAST", func(t *testing.T) {
		m := AddrtypeMatcher{dest: local}
		if got, _ := m.Match(stack.Prerouting, newIPv4Packet(t, "10.0.2.2", "10.0.2.15"), "eth0", ""); got {
			t.Errorf("unbound matcher matched LOCAL")
		}
	})
}

// marshalledData returns the match data of an entry match that marshalMatcher built.
func marshalledData(t *testing.T, m stack.Matcher) (linux.XTEntryMatch, []byte) {
	t.Helper()
	buf := marshalMatcher(m)
	var hdr linux.XTEntryMatch
	hdr.UnmarshalBytes(buf)
	if int(hdr.MatchSize) != len(buf) {
		t.Fatalf("MatchSize = %d, buffer has %d bytes", hdr.MatchSize, len(buf))
	}
	return hdr, buf[linux.SizeOfXTEntryMatch:]
}

func TestAddrtypeMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		matcher AddrtypeMatcher
		ipv6    bool
	}{
		{"rev0 dst LOCAL", AddrtypeMatcher{rev: 0, dest: linux.XT_ADDRTYPE_LOCAL}, false},
		{"rev0 inverted both", AddrtypeMatcher{rev: 0, source: linux.XT_ADDRTYPE_UNICAST, dest: linux.XT_ADDRTYPE_LOCAL | linux.XT_ADDRTYPE_BROADCAST, invertSource: true, invertDest: true}, false},
		{"rev1 dst LOCAL", AddrtypeMatcher{rev: 1, dest: linux.XT_ADDRTYPE_LOCAL}, false},
		{"rev1 all flags", AddrtypeMatcher{rev: 1, source: linux.XT_ADDRTYPE_UNICAST, dest: linux.XT_ADDRTYPE_LOCAL, invertSource: true, invertDest: true, limitIfaceIn: true}, false},
		{"rev1 limit out", AddrtypeMatcher{rev: 1, source: linux.XT_ADDRTYPE_LOCAL, limitIfaceOut: true}, false},
		{"rev1 IPv6", AddrtypeMatcher{rev: 1, dest: linux.XT_ADDRTYPE_LOCAL | linux.XT_ADDRTYPE_MULTICAST}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.matcher
			hdr, _ := marshalledData(t, &m)
			if got := hdr.Name.String(); got != matcherNameAddrtype {
				t.Errorf("name = %q, want %q", got, matcherNameAddrtype)
			}
			if hdr.Revision != m.rev {
				t.Errorf("revision = %d, want %d", hdr.Revision, m.rev)
			}

			filter := stack.EmptyFilter4()
			if tc.ipv6 {
				filter = stack.EmptyFilter6()
			}
			// parseMatchers is the production path that tries the highest revision first.
			parsed, err := parseMatchers(nil, filter, marshalMatcher(&m))
			if err != nil {
				t.Fatalf("parseMatchers: %v", err)
			}
			if len(parsed) != 1 {
				t.Fatalf("parseMatchers returned %d matchers, want 1", len(parsed))
			}
			got := *parsed[0].(*AddrtypeMatcher)
			if got != m {
				t.Errorf("round trip = %+v, want %+v", got, m)
			}
		})
	}
}

func TestAddrtypeUnmarshalKernelLayout(t *testing.T) {
	// Byte layouts from include/uapi/linux/netfilter/xt_addrtype.h on a
	// little-endian host.
	rev0 := []byte{
		0x00, 0x00, // source
		0x04, 0x00, // dest = LOCAL
		0x00, 0x00, 0x00, 0x00, // invert_source
		0x01, 0x00, 0x00, 0x00, // invert_dest
		0x00, 0x00, 0x00, 0x00, // alignment padding
	}
	m, err := addrtypeMarshaler{rev: 0}.unmarshal(nil, rev0, stack.EmptyFilter4())
	if err != nil {
		t.Fatalf("rev0 unmarshal: %v", err)
	}
	want := AddrtypeMatcher{rev: 0, dest: linux.XT_ADDRTYPE_LOCAL, invertDest: true}
	if got := *m.(*AddrtypeMatcher); got != want {
		t.Errorf("rev0 = %+v, want %+v", got, want)
	}

	rev1 := []byte{
		0x00, 0x00, // source
		0x04, 0x00, // dest = LOCAL
		0x06, 0x00, 0x00, 0x00, // flags = INVERT_DEST | LIMIT_IFACE_IN
	}
	m, err = addrtypeMarshaler{rev: 1}.unmarshal(nil, rev1, stack.EmptyFilter4())
	if err != nil {
		t.Fatalf("rev1 unmarshal: %v", err)
	}
	want = AddrtypeMatcher{rev: 1, dest: linux.XT_ADDRTYPE_LOCAL, invertDest: true, limitIfaceIn: true}
	if got := *m.(*AddrtypeMatcher); got != want {
		t.Errorf("rev1 = %+v, want %+v", got, want)
	}
}

func TestAddrtypeUnmarshalRejects(t *testing.T) {
	v1 := func(source, dest uint16, flags uint32) []byte {
		info := linux.XTAddrtypeInfoV1{Source: source, Dest: dest, Flags: flags}
		buf := make([]byte, info.SizeBytes())
		info.MarshalBytes(buf)
		return buf
	}
	tests := []struct {
		name   string
		rev    uint8
		buf    []byte
		filter stack.IPHeaderFilter
	}{
		{"rev1 short buffer", 1, make([]byte, 4), stack.EmptyFilter4()},
		{"rev1 long buffer", 1, make([]byte, 16), stack.EmptyFilter4()},
		{"rev0 short buffer", 0, make([]byte, 8), stack.EmptyFilter4()},
		{"rev0 with IPv6", 0, make([]byte, 16), stack.EmptyFilter6()},
		{"rev1 both interface limits", 1, v1(0, linux.XT_ADDRTYPE_LOCAL, linux.XT_ADDRTYPE_LIMIT_IFACE_IN|linux.XT_ADDRTYPE_LIMIT_IFACE_OUT), stack.EmptyFilter4()},
		{"rev1 IPv6 BROADCAST", 1, v1(0, linux.XT_ADDRTYPE_BROADCAST, 0), stack.EmptyFilter6()},
		{"rev1 IPv6 BLACKHOLE", 1, v1(linux.XT_ADDRTYPE_BLACKHOLE, 0, 0), stack.EmptyFilter6()},
		{"rev1 IPv6 PROHIBIT", 1, v1(0, linux.XT_ADDRTYPE_PROHIBIT, 0), stack.EmptyFilter6()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := (addrtypeMarshaler{rev: tc.rev}).unmarshal(nil, tc.buf, tc.filter); err == nil {
				t.Errorf("unmarshal succeeded, want an error")
			}
		})
	}
}

func TestAddrtypeRevisionNegotiation(t *testing.T) {
	// iptables asks IPT_SO_GET_REVISION_MATCH for the highest revision.
	rev, found := matchMakerRevision(matcherNameAddrtype, 0)
	if !found || rev != addrtypeRevision1 {
		t.Errorf("matchMakerRevision = (%d, %t), want (%d, true)", rev, found, addrtypeRevision1)
	}
}
