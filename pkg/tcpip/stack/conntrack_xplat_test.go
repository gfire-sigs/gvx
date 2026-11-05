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

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

var (
	ctClientAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	ctServerAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
)

const (
	ctClientPort = 41000
	ctServerPort = 80
)

// ctSegment is one TCP segment of a test connection.
type ctSegment struct {
	fromClient bool
	flags      header.TCPFlags
	seq, ack   uint32
	// payload is the number of data bytes.
	payload int
	// clientPort is the port of the client, or ctClientPort when it is 0.
	clientPort uint16
}

// ctPacket builds the IPv4 packet of a segment.
func ctPacket(s ctSegment) *PacketBuffer {
	src, dst := ctClientAddr, ctServerAddr
	srcPort, dstPort := uint16(ctClientPort), uint16(ctServerPort)
	if s.clientPort != 0 {
		srcPort = s.clientPort
	}
	if !s.fromClient {
		src, dst = dst, src
		srcPort, dstPort = dstPort, srcPort
	}
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: header.IPv4MinimumSize + header.TCPMinimumSize,
		Payload:            buffer.MakeWithData(make([]byte, s.payload)),
	})
	tcp := header.TCP(pkt.TransportHeader().Push(header.TCPMinimumSize))
	tcp.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     s.seq,
		AckNum:     s.ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      s.flags,
		WindowSize: 65535,
	})
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + header.TCPMinimumSize + s.payload),
		Protocol:    uint8(header.TCPProtocolNumber),
		TTL:         64,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.TCPProtocolNumber
	return pkt
}

// ctSend tracks the segment and finalizes the connection that carries it, as
// the iptables hooks do before the packet leaves.
func ctSend(t *testing.T, ct *ConnTrack, s ctSegment) *conn {
	t.Helper()
	pkt := ctPacket(s)
	defer pkt.DecRef()
	tup := ct.getConnAndUpdate(pkt, true /* skipChecksumValidation */)
	if tup == nil {
		t.Fatalf("segment %+v has no connection", s)
	}
	tup.conn.finalize()
	return tup.conn
}

func newTestConnTrack() *ConnTrack {
	ct := &ConnTrack{clock: faketime.NewManualClock()}
	ct.init()
	return ct
}

var ctHandshake = []ctSegment{
	{fromClient: true, flags: header.TCPFlagSyn, seq: 1000},
	{fromClient: false, flags: header.TCPFlagSyn | header.TCPFlagAck, seq: 5000, ack: 1001},
	{fromClient: true, flags: header.TCPFlagAck, seq: 1001, ack: 5001},
}

var ctClose = []ctSegment{
	{fromClient: true, flags: header.TCPFlagFin | header.TCPFlagAck, seq: 1001, ack: 5001},
	{fromClient: false, flags: header.TCPFlagAck, seq: 5001, ack: 1002},
	{fromClient: false, flags: header.TCPFlagFin | header.TCPFlagAck, seq: 5001, ack: 1002},
	{fromClient: true, flags: header.TCPFlagAck, seq: 1002, ack: 5002},
}

func ctRun(t *testing.T, ct *ConnTrack, segments []ctSegment) *conn {
	t.Helper()
	var cn *conn
	for _, s := range segments {
		cn = ctSend(t, ct, s)
	}
	return cn
}

// TestConnTrackSYNReopensClosedTCP checks that a SYN on the tuple of a closed
// connection starts a new connection, as Linux does for TIME_WAIT and CLOSE.
func TestConnTrackSYNReopensClosedTCP(t *testing.T) {
	syn := ctSegment{fromClient: true, flags: header.TCPFlagSyn, seq: 9000}
	reset := ctSegment{fromClient: false, flags: header.TCPFlagRst | header.TCPFlagAck, seq: 0, ack: 1001}
	closedHistory := append(append([]ctSegment{}, ctHandshake...), ctClose...)
	tests := []struct {
		name     string
		segments []ctSegment
		closed   bool // The state of the connection before the next segment.
		next     ctSegment
		wantNew  bool
	}{
		{"after the graceful close", closedHistory, true, syn, true},
		{"after a reset", []ctSegment{ctHandshake[0], reset}, true, syn, true},
		{"during the handshake", ctHandshake[:1], false, syn, false},
		{"on an established connection", ctHandshake, false, syn, false},
		{"after the close of one side", append(append([]ctSegment{}, ctHandshake...), ctClose[0]), false, syn, false},
		{"a SYN-ACK on a closed connection", closedHistory, true,
			ctSegment{fromClient: false, flags: header.TCPFlagSyn | header.TCPFlagAck, seq: 9000, ack: 9001}, false},
		{"an ACK on a closed connection", closedHistory, true,
			ctSegment{fromClient: true, flags: header.TCPFlagAck, seq: 1002, ack: 5002}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ct := newTestConnTrack()
			first := ctRun(t, ct, tc.segments)
			if got := first.closedTCP(); got != tc.closed {
				t.Fatalf("closedTCP after the setup = %t, want %t", got, tc.closed)
			}
			second := ctSend(t, ct, tc.next)
			if gotNew := second != first; gotNew != tc.wantNew {
				t.Errorf("segment %+v started a new connection = %t, want %t", tc.next, gotNew, tc.wantNew)
			}
			if tc.wantNew && !first.timedOut(ct.clock.NowMonotonic()) {
				t.Error("the old connection still answers lookups")
			}
		})
	}
}

// ctUDPPacket builds the IPv4 packet of a UDP datagram from the client to the
// server, from the given client port.
func ctUDPPacket(clientPort uint16) *PacketBuffer {
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: header.IPv4MinimumSize + header.UDPMinimumSize,
	})
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udp.Encode(&header.UDPFields{SrcPort: clientPort, DstPort: ctServerPort, Length: header.UDPMinimumSize})
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize + header.UDPMinimumSize,
		Protocol:    uint8(header.UDPProtocolNumber),
		TTL:         64,
		SrcAddr:     ctClientAddr,
		DstAddr:     ctServerAddr,
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	return pkt
}

// newConntrackStack returns a stack that holds only a connection table with
// one UDP flow for each of flows client ports, and it returns the original
// tuples of the flows.
func newConntrackStack(t *testing.T, flows int) (*Stack, []ConntrackTuple) {
	t.Helper()
	s := &Stack{tables: &IPTables{}}
	ct := &s.tables.connections
	ct.clock = faketime.NewManualClock()
	ct.init()
	var originals []ConntrackTuple
	for i := range flows {
		port := uint16(10000 + i)
		pkt := ctUDPPacket(port)
		tup := ct.getConnAndUpdate(pkt, true /* skipChecksumValidation */)
		if tup == nil || !tup.conn.finalize() {
			t.Fatalf("flow %d has no connection", i)
		}
		pkt.DecRef()
		originals = append(originals, ConntrackTuple{
			NetProto:   header.IPv4ProtocolNumber,
			TransProto: header.UDPProtocolNumber,
			Src:        ctClientAddr,
			Dst:        ctServerAddr,
			SrcPort:    port,
			DstPort:    ctServerPort,
		})
	}
	return s, originals
}

// scanAll reads the whole table with a ConntrackScan and returns the source
// ports of the connections, one count for each port.
func scanAll(s *Stack, afterBucket func(scanned int)) map[uint16]int {
	ports := make(map[uint16]int)
	scan := s.ConntrackScanner()
	for scanned := 1; ; scanned++ {
		entries, more := scan(nil)
		for _, e := range entries {
			ports[e.Original.SrcPort]++
		}
		if afterBucket != nil {
			afterBucket(scanned)
		}
		if !more {
			return ports
		}
	}
}

func TestConntrackScanReturnsEachConnectionOnce(t *testing.T) {
	const flows = 2000
	s, _ := newConntrackStack(t, flows)
	ports := scanAll(s, nil)
	if len(ports) != flows {
		t.Fatalf("scan found %d connections, want %d", len(ports), flows)
	}
	for port, n := range ports {
		if n != 1 {
			t.Errorf("port %d appeared %d times, want once", port, n)
		}
	}
	scan := s.ConntrackScanner()
	for range numBuckets {
		scan(nil)
	}
	if entries, more := scan(nil); len(entries) != 0 || more {
		t.Errorf("scan past the last bucket = %d entries and more %t, want none", len(entries), more)
	}
}

func TestConntrackScanKeepsConnectionsThatSurviveTableChanges(t *testing.T) {
	const flows = 1000
	s, tuples := newConntrackStack(t, flows)
	ct := &s.tables.connections
	deleted := map[uint16]bool{}
	extra := 0
	ports := scanAll(s, func(scanned int) {
		// Between two buckets, expire a connection and add a new one.
		if scanned%1000 != 0 {
			return
		}
		victim := tuples[len(deleted)]
		if _, ok := s.ConntrackDeleteTuple(victim, nil); !ok {
			t.Fatalf("connection %d does not exist", victim.SrcPort)
		}
		deleted[victim.SrcPort] = true
		pkt := ctUDPPacket(uint16(30000 + extra))
		defer pkt.DecRef()
		extra++
		if tup := ct.getConnAndUpdate(pkt, true); tup == nil || !tup.conn.finalize() {
			t.Fatal("the new flow has no connection")
		}
	})
	for _, tuple := range tuples {
		if deleted[tuple.SrcPort] {
			continue
		}
		if ports[tuple.SrcPort] != 1 {
			t.Errorf("connection %d that lived through the scan appeared %d times, want once", tuple.SrcPort, ports[tuple.SrcPort])
		}
	}
}

func TestConntrackLookupFindsEitherDirection(t *testing.T) {
	s, tuples := newConntrackStack(t, 50)
	original := tuples[7]
	reply := ConntrackTuple{
		NetProto:   original.NetProto,
		TransProto: original.TransProto,
		Src:        original.Dst,
		Dst:        original.Src,
		SrcPort:    original.DstPort,
		DstPort:    original.SrcPort,
	}
	for name, tuple := range map[string]ConntrackTuple{"original": original, "reply": reply} {
		e, ok := s.ConntrackLookup(tuple)
		if !ok || e.Original != original || e.Reply != reply {
			t.Errorf("lookup of the %s tuple = %+v, %t, want the connection with both tuples", name, e, ok)
		}
	}
	missing := original
	missing.SrcPort = 1
	if _, ok := s.ConntrackLookup(missing); ok {
		t.Error("lookup of an unknown tuple found a connection")
	}
}

func TestConntrackDeleteTupleExpiresOnlyThatConnection(t *testing.T) {
	s, tuples := newConntrackStack(t, 50)
	victim := tuples[7]
	reply := ConntrackTuple{
		NetProto:   victim.NetProto,
		TransProto: victim.TransProto,
		Src:        victim.Dst,
		Dst:        victim.Src,
		SrcPort:    victim.DstPort,
		DstPort:    victim.SrcPort,
	}
	refuse := func(ConntrackEntry) bool { return false }
	if _, ok := s.ConntrackDeleteTuple(victim, refuse); ok {
		t.Fatal("a refused delete expired the connection")
	}
	if _, ok := s.ConntrackLookup(victim); !ok {
		t.Fatal("a refused delete removed the connection")
	}
	e, ok := s.ConntrackDeleteTuple(reply, nil)
	if !ok || e.Original != victim {
		t.Fatalf("delete by reply tuple = %+v, %t, want the connection of %+v", e, ok, victim)
	}
	if _, ok := s.ConntrackLookup(victim); ok {
		t.Error("the connection still exists after the delete")
	}
	if _, ok := s.ConntrackDeleteTuple(victim, nil); ok {
		t.Error("a second delete found the connection")
	}
	if got := len(s.ConntrackEntries()); got != len(tuples)-1 {
		t.Errorf("table holds %d connections, want %d", got, len(tuples)-1)
	}
}
