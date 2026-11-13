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
	"math/rand"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// connmarkSpec is the user space view of the data of the CONNMARK target.
type connmarkSpec struct {
	rev                 uint8
	ctmark, ctmask      uint32
	nfmask              uint32
	mode                uint8
	shiftDir, shiftBits uint8
	overrideSize        int
	paddingByte         byte
}

// entry lays out the xt_entry_target as the iptables binary writes it.
func (s connmarkSpec) entry() []byte {
	size := connmarkTargetSize
	if s.overrideSize != 0 {
		size = s.overrideSize
	}
	buf := bytes.Repeat([]byte{0xaa}, size)
	hdr := linux.XTEntryTarget{TargetSize: uint16(size), Revision: s.rev}
	copy(hdr.Name[:], ConnmarkTargetName)
	hdr.MarshalUnsafe(buf)
	if size < connmarkTargetSize {
		return buf
	}
	binary.LittleEndian.PutUint32(buf[32:], s.ctmark)
	binary.LittleEndian.PutUint32(buf[36:], s.ctmask)
	binary.LittleEndian.PutUint32(buf[40:], s.nfmask)
	switch s.rev {
	case 1:
		buf[44] = s.mode
	case 2:
		buf[44], buf[45], buf[46] = s.shiftDir, s.shiftBits, s.mode
	}
	return buf
}

func parseConnmark(t *testing.T, filter stack.IPHeaderFilter, spec connmarkSpec) stack.Target {
	t.Helper()
	tgt, err := parseTarget(filter, spec.entry(), false, mangleTable)
	if err != nil {
		t.Fatalf("parseTarget(%+v): %v", spec, err)
	}
	if _, ok := tgt.(*connmarkTarget); !ok {
		t.Fatalf("parseTarget returned %T, want *connmarkTarget", tgt)
	}
	return tgt
}

// udpPacket returns an IPv4 UDP datagram. The reply direction swaps the
// addresses and the ports of the request.
func udpPacket(t *testing.T, reply bool) *stack.PacketBuffer {
	t.Helper()
	src, dst := addr4("10.0.0.1"), addr4("10.0.0.2")
	srcPort, dstPort := uint16(40000), uint16(51820)
	if reply {
		src, dst, srcPort, dstPort = dst, src, dstPort, srcPort
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.IPv4MinimumSize + header.UDPMinimumSize})
	t.Cleanup(pkt.DecRef)
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udp.Encode(&header.UDPFields{SrcPort: srcPort, DstPort: dstPort, Length: header.UDPMinimumSize})
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize + header.UDPMinimumSize,
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	return pkt
}

func newDefaultTables() *stack.IPTables {
	return stack.DefaultTables(faketime.NewManualClock(), rand.New(rand.NewSource(1)))
}

// setPrerouting replaces the PREROUTING rules of the mangle table. The
// connections of it stay.
func setPrerouting(it *stack.IPTables, rules ...stack.Rule) {
	// The default table ends each chain with the ACCEPT policy.
	defaults := newDefaultTables().GetTable(stack.MangleID, false)
	it.ForceReplaceTable(stack.MangleID, insertChainRules(defaults, stack.Prerouting, rules), false)
}

// mangleStack returns IPTables whose mangle table holds rules in PREROUTING.
func mangleStack(rules ...stack.Rule) *stack.IPTables {
	it := newDefaultTables()
	setPrerouting(it, rules...)
	return it
}

// trackedPacket sends a packet through PREROUTING of it, so that the packet
// holds its connection.
func trackedPacket(t *testing.T, it *stack.IPTables, reply bool) *stack.PacketBuffer {
	t.Helper()
	pkt := udpPacket(t, reply)
	if !it.CheckPrerouting(pkt, nil, "eth0") {
		t.Fatal("CheckPrerouting dropped the packet")
	}
	return pkt
}

func TestConnmarkTargetMath(t *testing.T) {
	const all = 0xffffffff
	tests := []struct {
		name string
		spec connmarkSpec
		// ctBefore and pktBefore are the marks before the target runs.
		ctBefore, pktBefore uint32
		// ctAfter and pktAfter are the marks after the target ran.
		ctAfter, pktAfter uint32
	}{
		{"set-mark", connmarkSpec{rev: 1, ctmark: 0x10, ctmask: all, mode: connmarkModeSet}, 0xff, 0x7, 0x10, 0x7},
		{"set-xmark with a mask", connmarkSpec{rev: 1, ctmark: 0x1, ctmask: 0xf0, mode: connmarkModeSet}, 0xab, 0, 0x0a, 0},
		{"and-mark", connmarkSpec{rev: 1, ctmark: 0, ctmask: ^uint32(0xff00), mode: connmarkModeSet}, 0x1234, 0, 0x1200, 0},
		{"or-mark", connmarkSpec{rev: 1, ctmark: 0x80, ctmask: 0x80, mode: connmarkModeSet}, 0x1, 0, 0x81, 0},
		{"xor-mark", connmarkSpec{rev: 1, ctmark: 0xff, ctmask: 0, mode: connmarkModeSet}, 0x0f, 0, 0xf0, 0},
		{"save-mark", connmarkSpec{rev: 1, ctmask: all, nfmask: all, mode: connmarkModeSave}, 0x5, 0xca6c, 0xca6c, 0xca6c},
		{"save-mark with masks", connmarkSpec{rev: 1, ctmask: 0xff00, nfmask: 0x00ff, mode: connmarkModeSave}, 0x1234, 0xabcd, 0x00f9, 0xabcd},
		{"restore-mark", connmarkSpec{rev: 1, ctmask: all, nfmask: all, mode: connmarkModeRestore}, 0xca6c, 0x5, 0xca6c, 0xca6c},
		{"restore-mark with masks", connmarkSpec{rev: 1, ctmask: 0xff, nfmask: 0xff00, mode: connmarkModeRestore}, 0xabcd, 0x1234, 0xabcd, 0x00f9},
		{"rev 2 set shifts left", connmarkSpec{rev: 2, ctmark: 0x3, ctmask: all, mode: connmarkModeSet, shiftBits: 4}, 0, 0, 0x30, 0},
		{"rev 2 set shifts right", connmarkSpec{rev: 2, ctmark: 0x30, ctmask: all, mode: connmarkModeSet, shiftDir: connmarkShiftRight, shiftBits: 4}, 0, 0, 0x3, 0},
		{"rev 2 save shifts the mark of the packet", connmarkSpec{rev: 2, ctmask: all, nfmask: 0xff, mode: connmarkModeSave, shiftBits: 8}, 0, 0x1ab, 0xab00, 0x1ab},
		{"rev 2 restore shifts the mark of the connection", connmarkSpec{rev: 2, ctmask: 0xff00, nfmask: all, mode: connmarkModeRestore, shiftDir: connmarkShiftRight, shiftBits: 8}, 0xab00, 0x7, 0xab00, 0xab},
		{"an unknown mode changes nothing", connmarkSpec{rev: 1, ctmark: 1, ctmask: all, nfmask: all, mode: 3}, 0x11, 0x22, 0x11, 0x22},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tgt := parseConnmark(t, stack.EmptyFilter4(), tc.spec)
			pkt := trackedPacket(t, mangleStack(), false)
			pkt.SetConnMark(tc.ctBefore)
			pkt.Mark = tc.pktBefore
			verdict, _ := tgt.Action(pkt, stack.Prerouting, nil, nil)
			if verdict != stack.RuleContinue {
				t.Errorf("verdict = %v, want RuleContinue", verdict)
			}
			if got := pkt.ConnMark(); got != tc.ctAfter {
				t.Errorf("connection mark = %#x, want %#x", got, tc.ctAfter)
			}
			if pkt.Mark != tc.pktAfter {
				t.Errorf("packet mark = %#x, want %#x", pkt.Mark, tc.pktAfter)
			}
		})
	}
}

func TestConnmarkTargetLeavesAnUntrackedPacketUnchanged(t *testing.T) {
	for _, mode := range []uint8{connmarkModeSet, connmarkModeSave, connmarkModeRestore} {
		tgt := parseConnmark(t, stack.EmptyFilter4(), connmarkSpec{rev: 1, ctmark: 1, ctmask: 0xffffffff, nfmask: 0xffffffff, mode: mode})
		pkt := udpPacket(t, false)
		pkt.Mark = 0x42
		if verdict, _ := tgt.Action(pkt, stack.Prerouting, nil, nil); verdict != stack.RuleContinue {
			t.Errorf("mode %d: verdict = %v, want RuleContinue", mode, verdict)
		}
		if pkt.Mark != 0x42 || pkt.ConnMark() != 0 {
			t.Errorf("mode %d: packet mark %#x, connection mark %#x, want 0x42 and 0", mode, pkt.Mark, pkt.ConnMark())
		}
	}
}

func TestConnmarkTargetRoundTripKeepsTheFields(t *testing.T) {
	for _, spec := range []connmarkSpec{
		{rev: 1, ctmark: 0x10, ctmask: 0xff, nfmask: 0xf0, mode: connmarkModeSave},
		{rev: 2, ctmark: 0xca6c, ctmask: 0xffff, nfmask: 0xff00, mode: connmarkModeRestore, shiftDir: connmarkShiftRight, shiftBits: 31},
	} {
		want := spec.entry()
		// Linux leaves the padding at zero, and the parse does not keep it.
		for i := range want {
			if i >= 45 && spec.rev == 1 || i >= 47 {
				want[i] = 0
			}
		}
		for name, filter := range map[string]stack.IPHeaderFilter{"ipv4": stack.EmptyFilter4(), "ipv6": stack.EmptyFilter6()} {
			tgt := parseConnmark(t, filter, spec)
			if got := marshalTarget(tgt); !bytes.Equal(got, want) {
				t.Errorf("rev %d %s: marshal = %x, want %x", spec.rev, name, got, want)
			}
		}
	}
}

func TestConnmarkTargetRejectsWhatLinuxRejects(t *testing.T) {
	tests := []struct {
		name string
		spec connmarkSpec
	}{
		{"rev 1 short", connmarkSpec{rev: 1, overrideSize: connmarkTargetSize - 8}},
		{"rev 1 long", connmarkSpec{rev: 1, overrideSize: connmarkTargetSize + 8}},
		{"rev 2 short", connmarkSpec{rev: 2, overrideSize: connmarkTargetSize - 8}},
		{"rev 2 shift of 32 bits", connmarkSpec{rev: 2, shiftBits: 32}},
		{"rev 2 shift direction 2", connmarkSpec{rev: 2, shiftDir: 2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseTarget(stack.EmptyFilter4(), tc.spec.entry(), false, mangleTable); err == nil {
				t.Errorf("parseTarget accepted %+v", tc.spec)
			}
		})
	}
	// Revision 0 and 3 do not exist.
	for _, rev := range []uint8{0, 3} {
		if _, err := parseTarget(stack.EmptyFilter4(), connmarkSpec{rev: rev}.entry(), false, mangleTable); err == nil {
			t.Errorf("parseTarget accepted revision %d", rev)
		}
	}
}

func TestConnmarkTargetIsValidInEveryTable(t *testing.T) {
	for _, table := range []string{rawTable, mangleTable, natTable, filterTable} {
		spec := connmarkSpec{rev: 1, ctmark: 1, ctmask: 1, mode: connmarkModeSet}
		if _, err := parseTarget(stack.EmptyFilter4(), spec.entry(), false, table); err != nil {
			t.Errorf("table %s: %v", table, err)
		}
	}
}

// connmarkMatchEntry returns the match entries of "-m connmark --mark".
func connmarkMatchEntry(mark, mask uint32, invert bool) []byte {
	m := NewConnmarkMatcher(mark, mask, invert)
	return marshalMatcher(m)
}

func TestConnmarkMatcherRoundTripAndRevision(t *testing.T) {
	for _, invert := range []bool{false, true} {
		entry := connmarkMatchEntry(0xca6c, 0xffff, invert)
		if got := entry[revisionOffset]; got != connmarkRevision {
			t.Errorf("revision byte = %d, want %d", got, connmarkRevision)
		}
		m := parseOneMatcher(t, stack.EmptyFilter4(), entry).(*ConnmarkMatcher)
		if m.mark != 0xca6c || m.mask != 0xffff || m.invert != invert {
			t.Errorf("parsed %+v, want mark 0xca6c, mask 0xffff, invert %t", *m, invert)
		}
		if got := marshalMatcher(m); !bytes.Equal(got, entry) {
			t.Errorf("marshal = %x, want %x", got, entry)
		}
	}
	short := connmarkMatchEntry(1, 1, false)
	short = short[:len(short)-8]
	if _, err := parseMatchers(nil, nil, stack.EmptyFilter4(), short); err == nil {
		t.Error("parseMatchers accepted a short connmark match")
	}
}

func TestConnmarkMatcherMatchesTheConnectionMark(t *testing.T) {
	tests := []struct {
		name       string
		mark, mask uint32
		invert     bool
		connMark   uint32
		want       bool
	}{
		{"equal", 0xca6c, 0xffffffff, false, 0xca6c, true},
		{"different", 0xca6c, 0xffffffff, false, 0xca6d, false},
		{"masked equal", 0x6c, 0xff, false, 0xca6c, true},
		{"inverted equal", 0xca6c, 0xffffffff, true, 0xca6c, false},
		{"inverted different", 0xca6c, 0xffffffff, true, 0x1, true},
		{"zero mark", 0, 0xffffffff, false, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := trackedPacket(t, mangleStack(), false)
			pkt.SetConnMark(tc.connMark)
			// The packet mark must not matter.
			pkt.Mark = ^tc.connMark
			got, hotdrop := NewConnmarkMatcher(tc.mark, tc.mask, tc.invert).Match(stack.Prerouting, pkt, "", "")
			if got != tc.want || hotdrop {
				t.Errorf("Match = %t, hotdrop %t, want %t", got, hotdrop, tc.want)
			}
		})
	}
}

func TestConnmarkMatcherNeverMatchesAnUntrackedPacket(t *testing.T) {
	for _, invert := range []bool{false, true} {
		pkt := udpPacket(t, false)
		if got, _ := NewConnmarkMatcher(0, 0xffffffff, invert).Match(stack.Prerouting, pkt, "", ""); got {
			t.Errorf("invert %t: untracked packet matched", invert)
		}
	}
}

// TestConnmarkRulesCarryTheMarkToTheReplyPacket runs the rules of wg-quick
// through PREROUTING. A rule saves the mark of a request in its connection. A
// rule on the reply restores it, and the match connmark selects the reply.
func TestConnmarkRulesCarryTheMarkToTheReplyPacket(t *testing.T) {
	filter := stack.EmptyFilter4()
	save := connmarkSpec{rev: 1, ctmask: 0xffffffff, nfmask: 0xffffffff, mode: connmarkModeSave}
	restore := connmarkSpec{rev: 1, ctmask: 0xffffffff, nfmask: 0xffffffff, mode: connmarkModeRestore}
	setMark := &markTarget{mark: 0xca6c, mask: 0xffffffff, networkProtocol: header.IPv4ProtocolNumber}
	drop := &dropTarget{DropTarget: stack.DropTarget{NetworkProtocol: header.IPv4ProtocolNumber}}

	it := mangleStack(
		stack.Rule{Filter: filter, Target: setMark},
		stack.Rule{Filter: filter, Target: parseConnmark(t, filter, save)},
	)
	request := trackedPacket(t, it, false)
	if request.Mark != 0xca6c || request.ConnMark() != 0xca6c {
		t.Fatalf("request: packet mark %#x, connection mark %#x, want 0xca6c for both", request.Mark, request.ConnMark())
	}
	if !request.FinalizeConnTrack() {
		t.Fatal("FinalizeConnTrack failed")
	}

	setPrerouting(it, stack.Rule{Filter: filter, Target: parseConnmark(t, filter, restore)})
	reply := trackedPacket(t, it, true)
	if reply.Mark != 0xca6c {
		t.Errorf("reply packet mark = %#x, want the saved 0xca6c", reply.Mark)
	}

	// The match connmark drops the reply and accepts a packet of another flow.
	setPrerouting(it, stack.Rule{Filter: filter, Matchers: []stack.Matcher{NewConnmarkMatcher(0xca6c, 0xffffffff, false)}, Target: drop})
	if it.CheckPrerouting(udpPacket(t, true), nil, "eth0") {
		t.Error("the reply with the saved mark passed the rule that drops the mark 0xca6c")
	}
	setPrerouting(it, stack.Rule{Filter: filter, Matchers: []stack.Matcher{NewConnmarkMatcher(0xca6c, 0xffffffff, true)}, Target: drop})
	if !it.CheckPrerouting(udpPacket(t, true), nil, "eth0") {
		t.Error("the reply passed the rule that drops every mark except 0xca6c")
	}
}
