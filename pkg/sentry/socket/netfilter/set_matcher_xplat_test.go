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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// Flags of the "set" match as iptables writes them.
const (
	testInvMatch   = uint8(ipset.KInvMatch)
	testDimOneSrc  = uint8(ipset.KDimOneSrc)
	testDimTwoSrc  = uint8(ipset.KDimTwoSrc)
	testNomatchBit = uint8(ipset.KReturnNomatch)
)

// setEnv is a network stack with a manual clock and the sets of the stack.
type setEnv struct {
	stk   *stack.Stack
	clock *faketime.ManualClock
	reg   *ipset.Registry
}

func newSetEnv(t *testing.T) *setEnv {
	t.Helper()
	clock := faketime.NewManualClock()
	stk := stack.New(stack.Options{Clock: clock})
	t.Cleanup(stk.Destroy)
	return &setEnv{stk: stk, clock: clock, reg: ipset.ForStack(stk, nil)}
}

// create makes a set of the type with its newest revision.
func (e *setEnv) create(t *testing.T, name, typeName string, family uint8, mod func(*ipset.CreateParams)) ipset.ID {
	t.Helper()
	_, maxRev, err := ipset.FindType(typeName, family)
	if err != nil {
		t.Fatalf("FindType(%q): %v", typeName, err)
	}
	p := &ipset.CreateParams{Name: name, TypeName: typeName, Family: family, Revision: maxRev}
	if mod != nil {
		mod(p)
	}
	if err := e.reg.Create(p); err != nil {
		t.Fatalf("Create(%q): %v", name, err)
	}
	id, _, ok := e.reg.Lookup(name)
	if !ok {
		t.Fatalf("Lookup(%q) failed after Create", name)
	}
	return id
}

func (e *setEnv) add(t *testing.T, name string, el ipset.Element) {
	t.Helper()
	if ret := e.reg.Uadt(name, ipset.AdtAdd, &el, 0); ret != 0 {
		t.Fatalf("add to %q: code %d", name, ret)
	}
}

// ipsetAddr returns the address of s in the form of the sets.
func ipsetAddr(s string) ipset.Addr {
	a := netip.MustParseAddr(s)
	var out ipset.Addr
	copy(out[:], a.AsSlice())
	return out
}

func hostElement(ip string) ipset.Element {
	return ipset.Element{Has: ipset.HasIP, IP: ipsetAddr(ip)}
}

func portElement(ip string, proto uint8, port uint16) ipset.Element {
	return ipset.Element{Has: ipset.HasIP | ipset.HasPort | ipset.HasProto, IP: ipsetAddr(ip), Proto: proto, Port: port}
}

// setMatchSpec is the user space view of the match data of the "set" match.
type setMatchSpec struct {
	rev          uint8
	index        ipset.ID
	dim, flags   uint8
	packetsOp    uint8
	packetsValue uint64
	bytesOp      uint8
	bytesValue   uint64
	cmdFlags     uint32
}

// data lays out the struct of the revision as the iptables binary writes it
// on a 64-bit little-endian host. Every padding byte has the value 0xaa, so
// that a test sees whether the kernel keeps the padding.
func (s setMatchSpec) data() []byte {
	data := bytes.Repeat([]byte{0xaa}, setMatchSize(s.rev)+(8-setMatchSize(s.rev)%8)%8)
	binary.LittleEndian.PutUint16(data[0:], uint16(s.index))
	data[2], data[3] = s.dim, s.flags
	switch s.rev {
	case setMatchRevision3:
		data[8] = s.packetsOp
		binary.LittleEndian.PutUint64(data[16:], s.packetsValue)
		data[24] = s.bytesOp
		binary.LittleEndian.PutUint64(data[32:], s.bytesValue)
		binary.LittleEndian.PutUint32(data[40:], s.cmdFlags)
	case setMatchRevision4:
		binary.LittleEndian.PutUint64(data[8:], s.packetsValue)
		data[16] = s.packetsOp
		binary.LittleEndian.PutUint64(data[24:], s.bytesValue)
		data[32] = s.bytesOp
		binary.LittleEndian.PutUint32(data[40:], s.cmdFlags)
	}
	return data
}

func (s setMatchSpec) entry() []byte {
	buf := marshalEntryMatch(matcherNameSet, s.data())
	buf[revisionOffset] = s.rev
	return buf
}

func parseSetMatch(t *testing.T, filter stack.IPHeaderFilter, spec setMatchSpec) *SetMatcher {
	t.Helper()
	parsed, err := parseMatchers(nil, filter, spec.entry())
	if err != nil {
		t.Fatalf("parseMatchers(%+v): %v", spec, err)
	}
	if len(parsed) != 1 {
		t.Fatalf("parseMatchers returned %d matchers, want 1", len(parsed))
	}
	m, ok := parsed[0].(*SetMatcher)
	if !ok {
		t.Fatalf("parseMatchers returned %T, want *SetMatcher", parsed[0])
	}
	return m
}

// bindSetMatch parses spec and binds it to the stack of env.
func (e *setEnv) bindSetMatch(t *testing.T, spec setMatchSpec) *SetMatcher {
	t.Helper()
	m := parseSetMatch(t, stack.EmptyFilter4(), spec)
	if err := bindMatcherStacks(e.stk, []stack.Rule{{Matchers: []stack.Matcher{m}}}); err != nil {
		t.Fatalf("bind %+v: %v", spec, err)
	}
	return m
}

// testPacket describes a packet that buildPacket makes.
type testPacket struct {
	src, dst     string
	proto        uint8
	srcPort      uint16
	dstPort      uint16
	payload      int
	fragOffset   uint16 // IPv4 fragment offset in bytes.
	moreFrags    bool
	inData       bool   // The transport header stays in the data, as before the parse.
	v6Extensions []byte // IPv6 extension headers that follow the IPv6 header.
}

func (p testPacket) transport() []byte {
	switch p.proto {
	case 6:
		b := make([]byte, header.TCPMinimumSize)
		binary.BigEndian.PutUint16(b[0:], p.srcPort)
		binary.BigEndian.PutUint16(b[2:], p.dstPort)
		return b
	case 17:
		b := make([]byte, header.UDPMinimumSize)
		binary.BigEndian.PutUint16(b[0:], p.srcPort)
		binary.BigEndian.PutUint16(b[2:], p.dstPort)
		return b
	case 1, 58:
		// The source port field holds the type and the code.
		b := make([]byte, 8)
		binary.BigEndian.PutUint16(b[0:], p.srcPort)
		return b
	}
	return nil
}

func buildPacket(t *testing.T, p testPacket) *stack.PacketBuffer {
	t.Helper()
	src := netip.MustParseAddr(p.src)
	tr := p.transport()
	netLen := header.IPv4MinimumSize
	if src.Is6() {
		netLen = header.IPv6MinimumSize + len(p.v6Extensions)
	}
	data := make([]byte, p.payload)
	reserve := netLen
	if p.inData {
		data = append(append([]byte(nil), tr...), data...)
	} else {
		reserve += len(tr)
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: reserve,
		Payload:            buffer.MakeWithData(data),
	})
	t.Cleanup(pkt.DecRef)
	if !p.inData && len(tr) > 0 {
		copy(pkt.TransportHeader().Push(len(tr)), tr)
	}
	total := netLen + len(tr) + p.payload
	if src.Is4() {
		hdr := header.IPv4(pkt.NetworkHeader().Push(netLen))
		flags := uint8(0)
		if p.moreFrags {
			flags = header.IPv4FlagMoreFragments
		}
		hdr.Encode(&header.IPv4Fields{
			TotalLength:    uint16(total),
			TTL:            64,
			Protocol:       p.proto,
			Flags:          flags,
			FragmentOffset: p.fragOffset,
			SrcAddr:        addr4(p.src),
			DstAddr:        addr4(p.dst),
		})
		pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
		return pkt
	}
	buf := pkt.NetworkHeader().Push(netLen)
	hdr := header.IPv6(buf)
	next := header.IPv6ExtensionHeaderIdentifier(p.proto)
	if len(p.v6Extensions) > 0 {
		next = header.IPv6HopByHopOptionsExtHdrIdentifier
		copy(buf[header.IPv6MinimumSize:], p.v6Extensions)
	}
	hdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(total - header.IPv6MinimumSize),
		TransportProtocol: 0,
		HopLimit:          64,
		SrcAddr:           addr6(p.src),
		DstAddr:           addr6(p.dst),
	})
	hdr[6] = uint8(next)
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
	return pkt
}

// tcpPacket is a TCP packet with a payload of 100 bytes.
func tcpPacket(src, dst string, srcPort, dstPort uint16) testPacket {
	return testPacket{src: src, dst: dst, proto: 6, srcPort: srcPort, dstPort: dstPort, payload: 100}
}

func matchSet(t *testing.T, m *SetMatcher, pkt *stack.PacketBuffer) bool {
	t.Helper()
	ok, hotdrop := m.Match(stack.Input, pkt, "", "")
	if hotdrop {
		t.Fatal("Match requested a hot drop")
	}
	return ok
}

func TestSetMatchRoundTripKeepsTheBytes(t *testing.T) {
	for _, spec := range []setMatchSpec{
		{rev: 1, index: 3, dim: 2, flags: testDimOneSrc | testInvMatch},
		{rev: 2, index: 4, dim: 1, flags: testDimOneSrc | testNomatchBit},
		{rev: 3, index: 5, dim: 3, flags: testDimOneSrc | testDimTwoSrc, packetsOp: ipset.CounterGT, packetsValue: 7, bytesOp: ipset.CounterLT, bytesValue: 1 << 40, cmdFlags: uint32(ipset.FlagSkipCounterUpdate)},
		{rev: 4, index: 6, dim: 1, flags: testInvMatch, packetsOp: ipset.CounterNE, packetsValue: 1 << 33, bytesOp: ipset.CounterEQ, bytesValue: 9, cmdFlags: uint32(ipset.FlagReturnNomatch)},
	} {
		want := spec.entry()
		for _, filter := range []stack.IPHeaderFilter{stack.EmptyFilter4(), stack.EmptyFilter6()} {
			m := parseSetMatch(t, filter, spec)
			if m.revision() != spec.rev {
				t.Errorf("rev %d: parsed revision %d", spec.rev, m.revision())
			}
			if got := marshalMatcher(m); !bytes.Equal(got, want) {
				t.Errorf("rev %d: marshal = %x, want %x", spec.rev, got, want)
			}
		}
	}
}

func TestSetMatchRejectsWrongSize(t *testing.T) {
	buf := setMatchSpec{rev: 4, index: 1, dim: 1}.entry()
	for _, size := range []int{0, 4, 8, 40, 56} {
		data := make([]byte, size)
		bad := marshalEntryMatch(matcherNameSet, data)
		bad[revisionOffset] = 4
		if _, err := parseMatchers(nil, stack.EmptyFilter4(), bad); err == nil {
			t.Errorf("parseMatchers accepted match data of %d bytes", size)
		}
	}
	if _, err := parseMatchers(nil, stack.EmptyFilter4(), buf); err != nil {
		t.Errorf("parseMatchers rejected a valid revision 4 match: %v", err)
	}
}

func TestSetMatchRevisionsAreReported(t *testing.T) {
	if rev, ok := matchMakerRevision(matcherNameSet, 0); !ok || rev != 4 {
		t.Errorf("matchMakerRevision(set) = %d, %t, want 4, true", rev, ok)
	}
	for _, proto := range []string{"ipv4", "ipv6"} {
		netProto := header.IPv4ProtocolNumber
		if proto == "ipv6" {
			netProto = header.IPv6ProtocolNumber
		}
		if rev, ok := targetRevision(SetTargetName, netProto, 9); !ok || rev != 3 {
			t.Errorf("%s: targetRevision(SET) = %d, %t, want 3, true", proto, rev, ok)
		}
	}
}

func TestSetMatchHashIPBySource(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "allow", "hash:ip", ipset.FamilyIPv4, nil)
	env.add(t, "allow", hostElement("192.0.2.1"))

	for _, rev := range []uint8{1, 2, 3, 4} {
		src := env.bindSetMatch(t, setMatchSpec{rev: rev, index: id, dim: 1, flags: testDimOneSrc})
		dst := env.bindSetMatch(t, setMatchSpec{rev: rev, index: id, dim: 1})
		inv := env.bindSetMatch(t, setMatchSpec{rev: rev, index: id, dim: 1, flags: testDimOneSrc | testInvMatch})

		pkt := buildPacket(t, tcpPacket("192.0.2.1", "198.51.100.7", 1000, 80))
		if !matchSet(t, src, pkt) {
			t.Errorf("rev %d: --match-set allow src missed the member source", rev)
		}
		if matchSet(t, dst, pkt) {
			t.Errorf("rev %d: --match-set allow dst matched a destination that is no member", rev)
		}
		if matchSet(t, inv, pkt) {
			t.Errorf("rev %d: ! --match-set allow src matched a member", rev)
		}
		other := buildPacket(t, tcpPacket("192.0.2.2", "192.0.2.1", 1000, 80))
		if matchSet(t, src, other) {
			t.Errorf("rev %d: --match-set allow src matched a source that is no member", rev)
		}
		if !matchSet(t, dst, other) {
			t.Errorf("rev %d: --match-set allow dst missed the member destination", rev)
		}
		if !matchSet(t, inv, other) {
			t.Errorf("rev %d: ! --match-set allow src missed a non-member", rev)
		}
	}
}

func TestSetMatchHashIPv6(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "six", "hash:ip", ipset.FamilyIPv6, nil)
	env.add(t, "six", hostElement("2001:db8::1"))
	m := parseSetMatch(t, stack.EmptyFilter6(), setMatchSpec{rev: 4, index: id, dim: 1, flags: testDimOneSrc})
	if err := bindMatcherStacks(env.stk, []stack.Rule{{Matchers: []stack.Matcher{m}}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if !matchSet(t, m, buildPacket(t, tcpPacket("2001:db8::1", "2001:db8::2", 1, 2))) {
		t.Error("the IPv6 member source did not match")
	}
	if matchSet(t, m, buildPacket(t, tcpPacket("2001:db8::3", "2001:db8::1", 1, 2))) {
		t.Error("an IPv6 non-member source matched")
	}
	// An IPv4 packet never matches a set of the IPv6 family.
	if matchSet(t, m, buildPacket(t, tcpPacket("192.0.2.1", "192.0.2.2", 1, 2))) {
		t.Error("an IPv4 packet matched an IPv6 set")
	}
}

func TestSetMatchHashIPPort(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "svc", "hash:ip,port", ipset.FamilyIPv4, nil)
	env.add(t, "svc", portElement("203.0.113.5", 6, 443))
	env.add(t, "svc", portElement("203.0.113.5", 1, 0x0800))

	// "--match-set svc dst,dst" selects the destination address and port.
	dstDst := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 2})
	// "--match-set svc src,dst" selects the source address and the destination port.
	srcDst := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 2, flags: testDimOneSrc})
	// "--match-set svc src,src" selects the source address and port.
	srcSrc := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 2, flags: testDimOneSrc | testDimTwoSrc})
	// A match with dimension 1 never matches a set of dimension 2.
	oneDim := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 1})

	tests := []struct {
		name   string
		pkt    testPacket
		m      *SetMatcher
		wantOK bool
	}{
		{"dst,dst hit", tcpPacket("10.0.0.1", "203.0.113.5", 5000, 443), dstDst, true},
		{"dst,dst wrong port", tcpPacket("10.0.0.1", "203.0.113.5", 5000, 444), dstDst, false},
		{"dst,dst wrong protocol", testPacket{src: "10.0.0.1", dst: "203.0.113.5", proto: 17, srcPort: 5000, dstPort: 443}, dstDst, false},
		{"src,dst hit", tcpPacket("203.0.113.5", "10.0.0.1", 5000, 443), srcDst, true},
		{"src,dst source port does not count", tcpPacket("203.0.113.5", "10.0.0.1", 443, 80), srcDst, false},
		{"src,src hit", tcpPacket("203.0.113.5", "10.0.0.1", 443, 80), srcSrc, true},
		{"src,src miss", tcpPacket("203.0.113.5", "10.0.0.1", 80, 443), srcSrc, false},
		{"one dimension never matches", tcpPacket("10.0.0.1", "203.0.113.5", 5000, 443), oneDim, false},
		{"icmp type and code", testPacket{src: "10.0.0.1", dst: "203.0.113.5", proto: 1, srcPort: 0x0800}, dstDst, true},
		{"icmp other type", testPacket{src: "10.0.0.1", dst: "203.0.113.5", proto: 1, srcPort: 0x0000}, dstDst, false},
		{"transport header still in the data", testPacket{src: "10.0.0.1", dst: "203.0.113.5", proto: 6, srcPort: 5000, dstPort: 443, payload: 10, inData: true, moreFrags: true}, dstDst, true},
		{"fragment after the first has no ports", testPacket{src: "10.0.0.1", dst: "203.0.113.5", proto: 6, payload: 10, fragOffset: 1480}, dstDst, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchSet(t, tc.m, buildPacket(t, tc.pkt)); got != tc.wantOK {
				t.Errorf("Match = %t, want %t", got, tc.wantOK)
			}
		})
	}

	t.Run("short transport data", func(t *testing.T) {
		pkt := buildPacket(t, testPacket{src: "10.0.0.1", dst: "203.0.113.5", proto: 6, inData: true, srcPort: 5000, dstPort: 443})
		// Cut the data to 10 bytes, fewer than a TCP header.
		pkt.Data().CapLength(10)
		if matchSet(t, dstDst, pkt) {
			t.Error("a TCP header of 10 bytes gave a port")
		}
	})
}

func TestSetMatchIPv6ExtensionHeaderBeforeTransport(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "svc6", "hash:ip,port", ipset.FamilyIPv6, nil)
	env.add(t, "svc6", portElement("2001:db8::9", 6, 8080))
	m := parseSetMatch(t, stack.EmptyFilter6(), setMatchSpec{rev: 4, index: id, dim: 2})
	if err := bindMatcherStacks(env.stk, []stack.Rule{{Matchers: []stack.Matcher{m}}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// A hop-by-hop header of 8 bytes that names TCP as the next header.
	ext := []byte{6, 0, 1, 4, 0, 0, 0, 0}
	pkt := buildPacket(t, testPacket{src: "2001:db8::1", dst: "2001:db8::9", proto: 6, srcPort: 1234, dstPort: 8080, payload: 20, v6Extensions: ext})
	if !matchSet(t, m, pkt) {
		t.Error("the port behind an extension header was not found")
	}
	pkt = buildPacket(t, testPacket{src: "2001:db8::1", dst: "2001:db8::9", proto: 6, srcPort: 1234, dstPort: 8081, payload: 20, v6Extensions: ext})
	if matchSet(t, m, pkt) {
		t.Error("another port behind an extension header matched")
	}
}

func TestSetMatchNomatchElements(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "nets", "hash:net", ipset.FamilyIPv4, nil)
	env.add(t, "nets", ipset.Element{Has: ipset.HasIP | ipset.HasCIDR, IP: ipsetAddr("10.0.0.0"), CIDR: 24})
	env.add(t, "nets", ipset.Element{
		Has: ipset.HasIP | ipset.HasCadtFlags, IP: ipsetAddr("10.0.0.5"), CadtFlags: ipset.CadtNomatch,
	})

	plain := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 1, flags: testDimOneSrc})
	returnNomatchV2 := env.bindSetMatch(t, setMatchSpec{rev: 2, index: id, dim: 1, flags: testDimOneSrc | testNomatchBit})
	returnNomatchV4 := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 1, flags: testDimOneSrc, cmdFlags: uint32(ipset.FlagReturnNomatch)})

	tests := []struct {
		src                     string
		wantPlain, wantNomatch2 bool
	}{
		{"10.0.0.1", true, false},
		{"10.0.0.5", false, true},
		{"10.0.1.1", false, false},
	}
	for _, tc := range tests {
		pkt := buildPacket(t, tcpPacket(tc.src, "192.0.2.1", 1, 2))
		if got := matchSet(t, plain, pkt); got != tc.wantPlain {
			t.Errorf("%s: plain match = %t, want %t", tc.src, got, tc.wantPlain)
		}
		if got := matchSet(t, returnNomatchV2, pkt); got != tc.wantNomatch2 {
			t.Errorf("%s: rev 2 --return-nomatch = %t, want %t", tc.src, got, tc.wantNomatch2)
		}
		if got := matchSet(t, returnNomatchV4, pkt); got != tc.wantNomatch2 {
			t.Errorf("%s: rev 4 --return-nomatch = %t, want %t", tc.src, got, tc.wantNomatch2)
		}
	}
}

func TestSetMatchCounterConditions(t *testing.T) {
	// A packet of 100 bytes of payload has 140 bytes in the IP packet.
	const packetLen = 140
	counters := func(p *ipset.CreateParams) { p.CadtFlags = ipset.CadtWithCounters }
	for _, rev := range []uint8{3, 4} {
		t.Run(fmt.Sprintf("rev%d", rev), func(t *testing.T) { testSetMatchCounters(t, rev, packetLen, counters) })
	}
}

func testSetMatchCounters(t *testing.T, rev uint8, packetLen uint64, counters func(*ipset.CreateParams)) {
	{
		t.Run("packets greater than", func(t *testing.T) {
			env := newSetEnv(t)
			id := env.create(t, "counted", "hash:ip", ipset.FamilyIPv4, counters)
			env.add(t, "counted", hostElement("192.0.2.1"))
			m := env.bindSetMatch(t, setMatchSpec{rev: rev, index: id, dim: 1, flags: testDimOneSrc, packetsOp: ipset.CounterGT, packetsValue: 2})
			var got []bool
			for range 4 {
				got = append(got, matchSet(t, m, buildPacket(t, tcpPacket("192.0.2.1", "192.0.2.9", 1, 2))))
			}
			want := []bool{false, false, true, true}
			if !slicesEqual(got, want) {
				t.Errorf("rev %d: --packets-gt 2 gave %v over four packets, want %v", rev, got, want)
			}
		})
		t.Run("bytes equal", func(t *testing.T) {
			env := newSetEnv(t)
			id := env.create(t, "counted", "hash:ip", ipset.FamilyIPv4, counters)
			env.add(t, "counted", hostElement("192.0.2.1"))
			m := env.bindSetMatch(t, setMatchSpec{rev: rev, index: id, dim: 1, flags: testDimOneSrc, bytesOp: ipset.CounterEQ, bytesValue: packetLen})
			first := matchSet(t, m, buildPacket(t, tcpPacket("192.0.2.1", "192.0.2.9", 1, 2)))
			second := matchSet(t, m, buildPacket(t, tcpPacket("192.0.2.1", "192.0.2.9", 1, 2)))
			if !first || second {
				t.Errorf("rev %d: --bytes-eq %d gave %t then %t, want true then false", rev, packetLen, first, second)
			}
		})
		t.Run("skip counter update", func(t *testing.T) {
			env := newSetEnv(t)
			id := env.create(t, "counted", "hash:ip", ipset.FamilyIPv4, counters)
			env.add(t, "counted", hostElement("192.0.2.1"))
			m := env.bindSetMatch(t, setMatchSpec{
				rev: rev, index: id, dim: 1, flags: testDimOneSrc,
				packetsOp: ipset.CounterEQ, packetsValue: 0, cmdFlags: uint32(ipset.FlagSkipCounterUpdate),
			})
			for i := range 3 {
				if !matchSet(t, m, buildPacket(t, tcpPacket("192.0.2.1", "192.0.2.9", 1, 2))) {
					t.Fatalf("rev %d: packet %d changed the counter although the rule skips the update", rev, i)
				}
			}
		})
	}
}

func slicesEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isIPSetError(err error, code int) bool {
	var e *ipset.Error
	return errors.As(err, &e) && e.Code == code
}

func TestSetMatchHoldsTheSetUntilTheRuleIsReleased(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "held", "hash:ip", ipset.FamilyIPv4, nil)
	m := parseSetMatch(t, stack.EmptyFilter4(), setMatchSpec{rev: 4, index: id, dim: 1})
	rules := []stack.Rule{{Matchers: []stack.Matcher{m}}}
	if err := bindMatcherStacks(env.stk, rules); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := env.reg.Destroy("held", false, false); !isIPSetError(err, ipset.ErrBusy) {
		t.Fatalf("Destroy of a set that a rule names = %v, want the busy error", err)
	}
	releaseMatcherStacks(rules)
	// A second release does not drop a reference that it never took.
	releaseMatcherStacks(rules)
	if err := env.reg.Destroy("held", false, false); err != nil {
		t.Fatalf("Destroy after the release = %v, want nil", err)
	}
}

func TestSetMatchTwoRulesNeedTwoReleases(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "twice", "hash:ip", ipset.FamilyIPv4, nil)
	a := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 1})
	b := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 1})
	releaseMatcherStacks([]stack.Rule{{Matchers: []stack.Matcher{a}}})
	if err := env.reg.Destroy("twice", false, false); !isIPSetError(err, ipset.ErrBusy) {
		t.Fatalf("Destroy with one rule left = %v, want the busy error", err)
	}
	releaseMatcherStacks([]stack.Rule{{Matchers: []stack.Matcher{b}}})
	if err := env.reg.Destroy("twice", false, false); err != nil {
		t.Fatalf("Destroy after both releases = %v, want nil", err)
	}
}

func TestSetMatchRejectsUnknownIndexAndDimension(t *testing.T) {
	env := newSetEnv(t)
	good := env.create(t, "good", "hash:ip", ipset.FamilyIPv4, nil)

	t.Run("unknown index", func(t *testing.T) {
		m := parseSetMatch(t, stack.EmptyFilter4(), setMatchSpec{rev: 4, index: 77, dim: 1})
		if err := bindMatcherStacks(env.stk, []stack.Rule{{Matchers: []stack.Matcher{m}}}); err != syserr.ErrNoFileOrDir {
			t.Errorf("bind of an unknown index = %v, want ENOENT", err)
		}
	})
	t.Run("invalid index", func(t *testing.T) {
		m := parseSetMatch(t, stack.EmptyFilter4(), setMatchSpec{rev: 4, index: ipset.InvalidID, dim: 1})
		if err := bindMatcherStacks(env.stk, []stack.Rule{{Matchers: []stack.Matcher{m}}}); err != syserr.ErrNoFileOrDir {
			t.Errorf("bind of the invalid index = %v, want ENOENT", err)
		}
	})
	t.Run("dimension over the limit", func(t *testing.T) {
		m := parseSetMatch(t, stack.EmptyFilter4(), setMatchSpec{rev: 4, index: good, dim: ipset.DimMax + 1})
		if err := bindMatcherStacks(env.stk, []stack.Rule{{Matchers: []stack.Matcher{m}}}); err != syserr.ErrRange {
			t.Errorf("bind of dimension 7 = %v, want ERANGE", err)
		}
	})
	t.Run("a failed bind keeps no reference", func(t *testing.T) {
		first := parseSetMatch(t, stack.EmptyFilter4(), setMatchSpec{rev: 4, index: good, dim: 1})
		second := parseSetMatch(t, stack.EmptyFilter4(), setMatchSpec{rev: 4, index: 77, dim: 1})
		rules := []stack.Rule{
			{Matchers: []stack.Matcher{first}},
			{Matchers: []stack.Matcher{second}},
		}
		if err := bindMatcherStacks(env.stk, rules); err != syserr.ErrNoFileOrDir {
			t.Fatalf("bind = %v, want ENOENT", err)
		}
		if err := env.reg.Destroy("good", false, false); err != nil {
			t.Errorf("Destroy after the failed bind = %v, want nil", err)
		}
	})
	t.Run("a stack without sets", func(t *testing.T) {
		bare := stack.New(stack.Options{})
		t.Cleanup(bare.Destroy)
		m := parseSetMatch(t, stack.EmptyFilter4(), setMatchSpec{rev: 4, index: 0, dim: 1})
		if err := bindMatcherStacks(bare, []stack.Rule{{Matchers: []stack.Matcher{m}}}); err != syserr.ErrNoFileOrDir {
			t.Errorf("bind on a stack without sets = %v, want ENOENT", err)
		}
	})
}

func TestSetMatchTimeoutOfElements(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "timed", "hash:ip", ipset.FamilyIPv4, func(p *ipset.CreateParams) {
		p.Given |= ipset.GivenTimeout
		p.Timeout = 30
	})
	env.add(t, "timed", hostElement("192.0.2.1"))
	m := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 1, flags: testDimOneSrc})
	if !matchSet(t, m, buildPacket(t, tcpPacket("192.0.2.1", "192.0.2.9", 1, 2))) {
		t.Fatal("a new element did not match")
	}
	env.clock.Advance(31 * time.Second)
	if matchSet(t, m, buildPacket(t, tcpPacket("192.0.2.1", "192.0.2.9", 1, 2))) {
		t.Fatal("an element matched after its timeout")
	}
}
