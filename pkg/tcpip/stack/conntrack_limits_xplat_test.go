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

package stack

import (
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// ctStateTimeouts gives every state timeout a value of its own, so a test can
// tell which timeout a connection uses. The two timeouts that shorten another
// timeout are longer than the state timeouts, so they do not apply.
var ctStateTimeouts = map[ConntrackTimeout]time.Duration{
	ConntrackTimeoutGeneric:           50 * time.Second,
	ConntrackTimeoutTCPSynSent:        11 * time.Second,
	ConntrackTimeoutTCPSynRecv:        12 * time.Second,
	ConntrackTimeoutTCPEstablished:    13 * time.Second,
	ConntrackTimeoutTCPFinWait:        14 * time.Second,
	ConntrackTimeoutTCPCloseWait:      15 * time.Second,
	ConntrackTimeoutTCPLastAck:        16 * time.Second,
	ConntrackTimeoutTCPTimeWait:       17 * time.Second,
	ConntrackTimeoutTCPClose:          18 * time.Second,
	ConntrackTimeoutTCPMaxRetrans:     100 * time.Second,
	ConntrackTimeoutTCPUnacknowledged: 101 * time.Second,
	ConntrackTimeoutUDP:               21 * time.Second,
	ConntrackTimeoutUDPStream:         22 * time.Second,
	ConntrackTimeoutICMP:              23 * time.Second,
	ConntrackTimeoutICMPv6:            24 * time.Second,
}

// newLimitsConnTrack returns a table with the timeouts of ctStateTimeouts and
// a small bucket count, so that an early drop reads every bucket.
func newLimitsConnTrack(buckets int) *ConnTrack {
	ct := newTestConnTrack()
	ct.mu.Lock()
	ct.buckets = make([]bucket, buckets)
	ct.mu.Unlock()
	ct.updateConfig(func(c *conntrackConfig) {
		for timeout, d := range ctStateTimeouts {
			c.timeouts[timeout] = d
		}
	})
	return ct
}

// ctSendPort is ctSend for the flow of a client port.
func ctSendPort(t *testing.T, ct *ConnTrack, port uint16, s ctSegment) (*conn, bool) {
	t.Helper()
	s.clientPort = port
	pkt := ctPacket(s)
	defer pkt.DecRef()
	tup, full := ct.trackPacket(pkt, true /* skipChecksumValidation */)
	if tup == nil {
		return nil, full
	}
	tup.conn.finalize()
	return tup.conn, full
}

// ctTimeout returns the time that the connection has left.
func ctTimeout(ct *ConnTrack, cn *conn) time.Duration {
	return cn.snapshot(ct.clock.NowMonotonic()).Timeout
}

func TestConnTrackTCPTimeoutFollowsState(t *testing.T) {
	// handshake and close are the segments of ctHandshake and ctClose.
	reset := ctSegment{fromClient: true, flags: header.TCPFlagRst | header.TCPFlagAck, seq: 1001, ack: 5001}
	tests := []struct {
		name      string
		segments  []ctSegment
		wantState uint8
		want      ConntrackTimeout
	}{
		{"SYN", ctHandshake[:1], ConntrackTCPSynSent, ConntrackTimeoutTCPSynSent},
		{"SYN-ACK", ctHandshake[:2], ConntrackTCPSynRecv, ConntrackTimeoutTCPSynRecv},
		{"handshake", ctHandshake, ConntrackTCPEstablished, ConntrackTimeoutTCPEstablished},
		{"FIN", append(append([]ctSegment{}, ctHandshake...), ctClose[0]), ConntrackTCPFinWait, ConntrackTimeoutTCPFinWait},
		{"ACK of the FIN", append(append([]ctSegment{}, ctHandshake...), ctClose[:2]...), ConntrackTCPCloseWait, ConntrackTimeoutTCPCloseWait},
		{"second FIN", append(append([]ctSegment{}, ctHandshake...), ctClose[:3]...), ConntrackTCPLastAck, ConntrackTimeoutTCPLastAck},
		{"last ACK", append(append([]ctSegment{}, ctHandshake...), ctClose...), ConntrackTCPTimeWait, ConntrackTimeoutTCPTimeWait},
		{"RST", append(append([]ctSegment{}, ctHandshake...), reset), ConntrackTCPClose, ConntrackTimeoutTCPClose},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ct := newLimitsConnTrack(64)
			cn := ctRun(t, ct, tc.segments)
			e := cn.snapshot(ct.clock.NowMonotonic())
			if e.TCPState != tc.wantState {
				t.Errorf("TCP state = %d, want %d", e.TCPState, tc.wantState)
			}
			want := ctStateTimeouts[tc.want]
			if e.Timeout != want {
				t.Fatalf("timeout = %v, want %v", e.Timeout, want)
			}
			clock := ct.clock.(*faketime.ManualClock)
			clock.Advance(want - time.Second)
			if cn.timedOut(clock.NowMonotonic()) {
				t.Errorf("the connection timed out %v early", time.Second)
			}
			clock.Advance(time.Second)
			if !cn.timedOut(clock.NowMonotonic()) {
				t.Error("the connection did not time out after its timeout")
			}
		})
	}
}

func TestConnTrackTCPDefaultTimeouts(t *testing.T) {
	ct := newTestConnTrack()
	for _, tc := range []struct {
		name     string
		segments []ctSegment
		want     time.Duration
	}{
		{"SYN_SENT", ctHandshake[:1], 2 * time.Minute},
		{"SYN_RECV", ctHandshake[:2], 60 * time.Second},
		{"ESTABLISHED", ctHandshake, 5 * 24 * time.Hour},
	} {
		cn := ctRun(t, ct, tc.segments)
		if got := ctTimeout(ct, cn); got != tc.want {
			t.Errorf("%s: timeout = %v, want %v", tc.name, got, tc.want)
		}
		ct = newTestConnTrack()
	}
}

func TestConnTrackTimeoutChangeAppliesToNextPacket(t *testing.T) {
	ct := newLimitsConnTrack(64)
	cn := ctRun(t, ct, ctHandshake)
	ct.updateConfig(func(c *conntrackConfig) { c.timeouts[ConntrackTimeoutTCPEstablished] = 5 * time.Second })
	if got := ctTimeout(ct, cn); got != 13*time.Second {
		t.Fatalf("a change of the timeout moved a connection that no packet touched: %v, want 13s", got)
	}
	ack := ctSegment{fromClient: true, flags: header.TCPFlagAck, seq: 1001, ack: 5001}
	cn = ctSend(t, ct, ack)
	if got := ctTimeout(ct, cn); got != 5*time.Second {
		t.Errorf("timeout after the next packet = %v, want 5s", got)
	}
}

func TestConnTrackSnapshotReportsTheTimeLeft(t *testing.T) {
	ct := newLimitsConnTrack(64)
	cn := ctRun(t, ct, ctHandshake)
	clock := ct.clock.(*faketime.ManualClock)
	clock.Advance(5 * time.Second)
	if got := ctTimeout(ct, cn); got != 8*time.Second {
		t.Errorf("time left after 5 of 13 seconds = %v, want 8s", got)
	}
	clock.Advance(20 * time.Second)
	if got := ctTimeout(ct, cn); got != 0 {
		t.Errorf("time left after the timeout = %v, want 0", got)
	}
}

func TestConnTrackTCPRepeatedSYNKeepsTimeout(t *testing.T) {
	ct := newLimitsConnTrack(64)
	syn := ctHandshake[0]
	cn := ctSend(t, ct, syn)
	clock := ct.clock.(*faketime.ManualClock)
	clock.Advance(5 * time.Second)
	ctSend(t, ct, syn)
	if got := ctTimeout(ct, cn); got != 6*time.Second {
		t.Errorf("timeout after a repeated SYN = %v, want 6s", got)
	}
}

func TestConnTrackTCPRSTWithoutReplyDeletesConnection(t *testing.T) {
	ct := newLimitsConnTrack(64)
	cn := ctSend(t, ct, ctHandshake[0])
	ctSend(t, ct, ctSegment{fromClient: true, flags: header.TCPFlagRst, seq: 1001})
	if !cn.timedOut(ct.clock.NowMonotonic()) {
		t.Error("a RST of the client before any reply left the connection in the table")
	}
}

func TestConnTrackTCPUnacknowledgedDataShortensTimeout(t *testing.T) {
	ct := newLimitsConnTrack(64)
	ct.updateConfig(func(c *conntrackConfig) {
		c.timeouts[ConntrackTimeoutTCPUnacknowledged] = 7 * time.Second
	})
	cn := ctRun(t, ct, ctHandshake)
	data := ctSegment{fromClient: true, flags: header.TCPFlagAck, seq: 1001, ack: 5001, payload: 100}
	cn = ctSend(t, ct, data)
	if got := ctTimeout(ct, cn); got != 7*time.Second {
		t.Fatalf("timeout with unacknowledged data = %v, want 7s", got)
	}
	ack := ctSegment{fromClient: false, flags: header.TCPFlagAck, seq: 5001, ack: 1101}
	cn = ctSend(t, ct, ack)
	if got := ctTimeout(ct, cn); got != 13*time.Second {
		t.Errorf("timeout after the ACK of the data = %v, want the ESTABLISHED timeout 13s", got)
	}
}

func TestConnTrackTCPRepeatedACKShortensTimeout(t *testing.T) {
	ct := newLimitsConnTrack(64)
	ct.updateConfig(func(c *conntrackConfig) {
		c.timeouts[ConntrackTimeoutTCPMaxRetrans] = 9 * time.Second
		c.tcpMaxRetrans = 2
	})
	cn := ctRun(t, ct, ctHandshake)
	dup := ctHandshake[2]
	// The first repeat makes retrans 1. The second repeat reaches the maximum 2.
	for i, want := range []time.Duration{13 * time.Second, 9 * time.Second, 9 * time.Second} {
		cn = ctSend(t, ct, dup)
		if got := ctTimeout(ct, cn); got != want {
			t.Errorf("timeout after repeat %d = %v, want %v", i+1, got, want)
		}
	}
}

func TestConnTrackTCPAssuredAfterEstablished(t *testing.T) {
	ct := newLimitsConnTrack(64)
	for i, s := range ctHandshake {
		cn := ctSend(t, ct, s)
		assured := cn.snapshot(ct.clock.NowMonotonic()).Status&ConntrackStatusAssured != 0
		if want := i == 2; assured != want {
			t.Errorf("assured after segment %d = %t, want %t", i, assured, want)
		}
	}
}

func TestConnTrackFirstTCPPacketMustBeSYNOrACK(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags header.TCPFlags
		want  bool
	}{
		{"SYN", header.TCPFlagSyn, true},
		{"ACK", header.TCPFlagAck, true},
		{"SYN-ACK", header.TCPFlagSyn | header.TCPFlagAck, false},
		{"FIN-ACK", header.TCPFlagFin | header.TCPFlagAck, false},
		{"RST", header.TCPFlagRst, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := newLimitsConnTrack(64)
			pkt := ctPacket(ctSegment{fromClient: true, flags: tc.flags, seq: 1000, ack: 1})
			defer pkt.DecRef()
			tup, _ := ct.trackPacket(pkt, true)
			if got := tup != nil; got != tc.want {
				t.Errorf("a first packet with these flags created a connection = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestConnTrackUDPTimeouts(t *testing.T) {
	ct := newLimitsConnTrack(64)
	clock := ct.clock.(*faketime.ManualClock)
	send := func(reply bool) *conn {
		t.Helper()
		pkt := ctUDPPacket(10000)
		defer pkt.DecRef()
		if reply {
			ip := header.IPv4(pkt.NetworkHeader().Slice())
			udp := header.UDP(pkt.TransportHeader().Slice())
			src, dst := ip.SourceAddress(), ip.DestinationAddress()
			ip.SetSourceAddress(dst)
			ip.SetDestinationAddress(src)
			udp.SetSourcePort(ctServerPort)
			udp.SetDestinationPort(10000)
		}
		tup, _ := ct.trackPacket(pkt, true)
		if tup == nil {
			t.Fatal("no connection")
		}
		tup.conn.finalize()
		return tup.conn
	}
	assured := func(cn *conn) bool {
		return cn.snapshot(clock.NowMonotonic()).Status&ConntrackStatusAssured != 0
	}

	cn := send(false)
	if got := ctTimeout(ct, cn); got != 21*time.Second || assured(cn) {
		t.Fatalf("flow without a reply: timeout %v assured %t, want 21s and not assured", got, assured(cn))
	}
	cn = send(true)
	if got := ctTimeout(ct, cn); got != 21*time.Second || assured(cn) {
		t.Fatalf("reply in the first two seconds: timeout %v assured %t, want 21s and not assured", got, assured(cn))
	}
	clock.Advance(3 * time.Second)
	cn = send(false)
	if got := ctTimeout(ct, cn); got != 22*time.Second || !assured(cn) {
		t.Errorf("stream: timeout %v assured %t, want 22s and assured", got, assured(cn))
	}
}

func TestConnTrackICMPTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  func() *PacketBuffer
		want time.Duration
	}{
		{"ICMPv4", ctICMPv4EchoPacket, 23 * time.Second},
		{"ICMPv6", ctICMPv6EchoPacket, 24 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := newLimitsConnTrack(64)
			pkt := tc.pkt()
			defer pkt.DecRef()
			tup, _ := ct.trackPacket(pkt, true)
			if tup == nil {
				t.Fatal("no connection")
			}
			tup.conn.finalize()
			if got := ctTimeout(ct, tup.conn); got != tc.want {
				t.Errorf("timeout = %v, want %v", got, tc.want)
			}
		})
	}
}

// ctICMPv4EchoPacket builds an ICMPv4 echo request from the client.
func ctICMPv4EchoPacket() *PacketBuffer {
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: header.IPv4MinimumSize + header.ICMPv4MinimumSize,
	})
	icmp := header.ICMPv4(pkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetIdent(77)
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize + header.ICMPv4MinimumSize,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		TTL:         64,
		SrcAddr:     ctClientAddr,
		DstAddr:     ctServerAddr,
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber
	return pkt
}

// ctICMPv6EchoPacket builds an ICMPv6 echo request from the client.
func ctICMPv6EchoPacket() *PacketBuffer {
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: header.IPv6MinimumSize + header.ICMPv6MinimumSize,
	})
	icmp := header.ICMPv6(pkt.TransportHeader().Push(header.ICMPv6MinimumSize))
	icmp.SetType(header.ICMPv6EchoRequest)
	icmp.SetIdent(77)
	ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     header.ICMPv6MinimumSize,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16([16]byte{0: 0xfd, 15: 1}),
		DstAddr:           tcpip.AddrFrom16([16]byte{0: 0xfd, 15: 2}),
	})
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
	pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	return pkt
}

func TestConnTrackReaperReleasesCount(t *testing.T) {
	ct := newTestConnTrack()
	clock := ct.clock.(*faketime.ManualClock)
	for i := range 20 {
		pkt := ctUDPPacket(uint16(10000 + i))
		tup, _ := ct.trackPacket(pkt, true)
		tup.conn.finalize()
		pkt.DecRef()
	}
	if got := ct.count.Load(); got != 20 {
		t.Fatalf("count after 20 flows = %d, want 20", got)
	}
	clock.Advance(31 * time.Second)
	bucket, interval := 0, time.Second
	for range 128 {
		bucket, interval = ct.reapUnused(bucket, interval)
	}
	if got := ct.count.Load(); got != 0 {
		t.Errorf("count after the timeout and a full reaper pass = %d, want 0", got)
	}
}

// fillAssured sends a handshake on each of the ports, which makes each flow
// assured.
func fillAssured(t *testing.T, ct *ConnTrack, ports ...uint16) {
	t.Helper()
	for _, port := range ports {
		for _, s := range ctHandshake {
			if _, full := ctSendPort(t, ct, port, s); full {
				t.Fatalf("the table is full at port %d", port)
			}
		}
	}
}

func TestConnTrackFullTableDropsNewFlowOfAssuredTable(t *testing.T) {
	ct := newLimitsConnTrack(8)
	ct.limit.Store(NewConntrackLimit(2))
	fillAssured(t, ct, 41001, 41002)
	if got := ct.count.Load(); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
	cn, full := ctSendPort(t, ct, 41003, ctHandshake[0])
	if cn != nil || !full {
		t.Fatalf("new flow on a full table of assured flows: connection %t, full %t, want a drop", cn != nil, full)
	}
	if got := ct.count.Load(); got != 2 {
		t.Errorf("count after the drop = %d, want 2", got)
	}
	// Packets of the flows in the table still pass.
	if _, full := ctSendPort(t, ct, 41001, ctHandshake[2]); full {
		t.Error("a packet of an existing flow was dropped")
	}
}

func TestConnTrackFullTableEarlyDropsUnassuredFlow(t *testing.T) {
	ct := newLimitsConnTrack(8)
	ct.limit.Store(NewConntrackLimit(2))
	fillAssured(t, ct, 41001)
	// One UDP flow that has no reply fills the table.
	udp := ctUDPPacket(10000)
	tup, _ := ct.trackPacket(udp, true)
	tup.conn.finalize()
	udp.DecRef()

	cn, full := ctSendPort(t, ct, 41002, ctHandshake[0])
	if cn == nil || full {
		t.Fatalf("new flow on a table with an unassured flow: connection %t, full %t, want a new connection", cn != nil, full)
	}
	if got := ct.count.Load(); got != 2 {
		t.Errorf("count after the early drop = %d, want 2", got)
	}
	udpTuple := ConntrackTuple{
		NetProto: header.IPv4ProtocolNumber, TransProto: header.UDPProtocolNumber,
		Src: ctClientAddr, Dst: ctServerAddr, SrcPort: 10000, DstPort: ctServerPort,
	}
	if ct.confirmedForTuple(udpTuple) != nil {
		t.Error("the early drop left the UDP flow in the table")
	}
	tcpTuple := ConntrackTuple{
		NetProto: header.IPv4ProtocolNumber, TransProto: header.TCPProtocolNumber,
		Src: ctClientAddr, Dst: ctServerAddr, SrcPort: 41001, DstPort: ctServerPort,
	}
	if ct.confirmedForTuple(tcpTuple) == nil {
		t.Error("the early drop removed the assured flow")
	}
}

func TestConnTrackFullTableReclaimsTimedOutFlow(t *testing.T) {
	ct := newLimitsConnTrack(8)
	ct.limit.Store(NewConntrackLimit(1))
	fillAssured(t, ct, 41001)
	ct.updateConfig(func(c *conntrackConfig) { c.timeouts[ConntrackTimeoutTCPEstablished] = time.Second })
	// The next packet of the flow applies the short timeout.
	ctSendPort(t, ct, 41001, ctHandshake[2])
	ct.clock.(*faketime.ManualClock).Advance(2 * time.Second)
	if cn, full := ctSendPort(t, ct, 41002, ctHandshake[0]); cn == nil || full {
		t.Errorf("new flow after the old flow timed out: connection %t, full %t, want a new connection", cn != nil, full)
	}
}

func TestConnTrackLimitZeroMeansUnlimited(t *testing.T) {
	ct := newLimitsConnTrack(8)
	ct.limit.Store(NewConntrackLimit(0))
	for port := uint16(41001); port < 41041; port++ {
		if cn, full := ctSendPort(t, ct, port, ctHandshake[0]); cn == nil || full {
			t.Fatalf("flow %d was refused with no limit", port)
		}
	}
}

func TestConnTrackLimitIsUnsigned(t *testing.T) {
	// Linux stores nf_conntrack_max as an unsigned integer. A guest that
	// writes -1 sets the largest limit.
	l := NewConntrackLimit(uint32(0xffffffff))
	ct := newLimitsConnTrack(8)
	ct.limit.Store(l)
	for port := uint16(41001); port < 41011; port++ {
		if cn, full := ctSendPort(t, ct, port, ctHandshake[0]); cn == nil || full {
			t.Fatalf("flow %d was refused under the largest limit", port)
		}
	}
}

func TestConntrackLimitSharedBetweenStacks(t *testing.T) {
	shared := NewConntrackLimit(DefaultConntrackMax)
	var stacks [2]*Stack
	for i := range stacks {
		stacks[i] = &Stack{tables: &IPTables{}}
		stacks[i].SetConntrackLimit(shared)
	}
	shared.SetMax(5)
	for i, s := range stacks {
		if got := s.ConntrackLimit().Max(); got != 5 {
			t.Errorf("stack %d sees the limit %d, want 5", i, got)
		}
	}
}

func TestConntrackTimeoutsBelongToTheStack(t *testing.T) {
	a, b := &Stack{tables: &IPTables{}}, &Stack{tables: &IPTables{}}
	for timeout := ConntrackTimeoutGeneric; timeout < numConntrackTimeouts; timeout++ {
		if got, want := a.ConntrackTimeout(timeout), DefaultConntrackTimeout(timeout); got != want {
			t.Errorf("timeout %d = %v, want the default %v", timeout, got, want)
		}
	}
	a.SetConntrackTimeout(ConntrackTimeoutTCPEstablished, 5*time.Second)
	a.SetConntrackTCPMaxRetrans(9)
	if got := b.ConntrackTimeout(ConntrackTimeoutTCPEstablished); got != 5*24*time.Hour {
		t.Errorf("the other stack has timeout %v, want the default", got)
	}
	if got := b.ConntrackTCPMaxRetrans(); got != 3 {
		t.Errorf("the other stack has max retrans %d, want 3", got)
	}
	if got := a.ConntrackTCPMaxRetrans(); got != 9 {
		t.Errorf("max retrans = %d, want 9", got)
	}
}

func TestConntrackLinuxDefaultTimeouts(t *testing.T) {
	want := map[ConntrackTimeout]time.Duration{
		ConntrackTimeoutGeneric:           600 * time.Second,
		ConntrackTimeoutTCPSynSent:        120 * time.Second,
		ConntrackTimeoutTCPSynRecv:        60 * time.Second,
		ConntrackTimeoutTCPEstablished:    432000 * time.Second,
		ConntrackTimeoutTCPFinWait:        120 * time.Second,
		ConntrackTimeoutTCPCloseWait:      60 * time.Second,
		ConntrackTimeoutTCPLastAck:        30 * time.Second,
		ConntrackTimeoutTCPTimeWait:       120 * time.Second,
		ConntrackTimeoutTCPClose:          10 * time.Second,
		ConntrackTimeoutTCPMaxRetrans:     300 * time.Second,
		ConntrackTimeoutTCPUnacknowledged: 300 * time.Second,
		ConntrackTimeoutUDP:               30 * time.Second,
		ConntrackTimeoutUDPStream:         120 * time.Second,
		ConntrackTimeoutICMP:              30 * time.Second,
		ConntrackTimeoutICMPv6:            30 * time.Second,
	}
	for timeout, d := range want {
		if got := DefaultConntrackTimeout(timeout); got != d {
			t.Errorf("default of timeout %d = %v, want %v", timeout, got, d)
		}
	}
}
