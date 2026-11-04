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
}

// ctPacket builds the IPv4 packet of a segment.
func ctPacket(s ctSegment) *PacketBuffer {
	src, dst := ctClientAddr, ctServerAddr
	srcPort, dstPort := uint16(ctClientPort), uint16(ctServerPort)
	if !s.fromClient {
		src, dst = dst, src
		srcPort, dstPort = dstPort, srcPort
	}
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: header.IPv4MinimumSize + header.TCPMinimumSize,
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
		TotalLength: header.IPv4MinimumSize + header.TCPMinimumSize,
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
