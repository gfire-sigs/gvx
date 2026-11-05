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
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcpconntrack"
)

// This file gives each tracked connection the timeout that Linux gives it. The
// timeout depends on the protocol and, for TCP, on the state of the
// connection. A packet moves the connection to a new state and sets the
// expiry time to the packet time plus the timeout of the new state.
//
// Ref: net/netfilter/nf_conntrack_proto_tcp.c (tcp_conntracks and
// nf_conntrack_tcp_packet), nf_conntrack_proto_udp.c (nf_conntrack_udp_packet),
// nf_conntrack_proto_icmp.c, nf_conntrack_proto_icmpv6.c, and
// nf_conntrack_proto_generic.c.

// Pseudo states of the table of TCP transitions.
const (
	// tcpInvalid marks a packet that is not valid in the state. Linux
	// accepts the packet and does not change the connection.
	tcpInvalid uint8 = 10
	// tcpIgnore marks a packet that may be valid, but that the tracker
	// cannot judge. The tracker does not change the connection.
	tcpIgnore uint8 = 11
)

// Packet classes of the table of TCP transitions, as enum tcp_bit_set.
const (
	tcpSyn = iota
	tcpSynAck
	tcpFin
	tcpAck
	tcpRst
	tcpNone
)

// Directions of the table of TCP transitions.
const (
	tcpDirOriginal = 0
	tcpDirReply    = 1
)

const (
	sNO  = ConntrackTCPNone
	sSS  = ConntrackTCPSynSent
	sSR  = ConntrackTCPSynRecv
	sES  = ConntrackTCPEstablished
	sFW  = ConntrackTCPFinWait
	sCW  = ConntrackTCPCloseWait
	sLA  = ConntrackTCPLastAck
	sTW  = ConntrackTCPTimeWait
	sCL  = ConntrackTCPClose
	sS2  = ConntrackTCPSynSent2
	sIV  = tcpInvalid
	sIG  = tcpIgnore
	nTCP = int(ConntrackTCPSynSent2) + 1
)

// tcpTransitions is tcp_conntracks of Linux: the next state for a direction, a
// packet class, and the state of the connection. The columns are the states
// NONE, SYN_SENT, SYN_RECV, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, LAST_ACK,
// TIME_WAIT, CLOSE, and SYN_SENT2.
var tcpTransitions = [2][6][nTCP]uint8{
	tcpDirOriginal: {
		tcpSyn:    {sSS, sSS, sIG, sIG, sIG, sIG, sIG, sSS, sSS, sS2},
		tcpSynAck: {sIV, sIV, sSR, sIV, sIV, sIV, sIV, sIV, sIV, sSR},
		tcpFin:    {sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV},
		tcpAck:    {sES, sIV, sES, sES, sCW, sCW, sTW, sTW, sCL, sIV},
		tcpRst:    {sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL},
		tcpNone:   {sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV},
	},
	tcpDirReply: {
		tcpSyn:    {sIV, sS2, sIV, sIV, sIV, sIV, sIV, sSS, sIV, sS2},
		tcpSynAck: {sIV, sSR, sIG, sIG, sIG, sIG, sIG, sIG, sIG, sSR},
		tcpFin:    {sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV},
		tcpAck:    {sIV, sIG, sSR, sES, sCW, sCW, sTW, sTW, sCL, sIG},
		tcpRst:    {sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL},
		tcpNone:   {sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV},
	},
}

// tcpStateTimeout maps a TCP state to the timeout of the state.
var tcpStateTimeout = [nTCP]ConntrackTimeout{
	ConntrackTCPSynSent:     ConntrackTimeoutTCPSynSent,
	ConntrackTCPSynRecv:     ConntrackTimeoutTCPSynRecv,
	ConntrackTCPEstablished: ConntrackTimeoutTCPEstablished,
	ConntrackTCPFinWait:     ConntrackTimeoutTCPFinWait,
	ConntrackTCPCloseWait:   ConntrackTimeoutTCPCloseWait,
	ConntrackTCPLastAck:     ConntrackTimeoutTCPLastAck,
	ConntrackTCPTimeWait:    ConntrackTimeoutTCPTimeWait,
	ConntrackTCPClose:       ConntrackTimeoutTCPClose,
	ConntrackTCPSynSent2:    conntrackTimeoutTCPSynSent2,
}

// tcpClass returns the packet class of the flags, as get_conntrack_index.
func tcpClass(flags header.TCPFlags) int {
	switch {
	case flags&header.TCPFlagRst != 0:
		return tcpRst
	case flags&header.TCPFlagSyn != 0:
		if flags&header.TCPFlagAck != 0 {
			return tcpSynAck
		}
		return tcpSyn
	case flags&header.TCPFlagFin != 0:
		return tcpFin
	case flags&header.TCPFlagAck != 0:
		return tcpAck
	}
	return tcpNone
}

// startsTCPConn reports whether a TCP packet may create a connection. Linux
// creates a connection for a SYN, and with nf_conntrack_tcp_loose at its
// default of 1 also for an ACK, which picks up a connection in mid-stream.
func startsTCPConn(flags header.TCPFlags) bool {
	return tcpTransitions[tcpDirOriginal][tcpClass(flags)][sNO] < sIV
}

// tcpSeen is what the tracker knows of one direction of a TCP connection.
type tcpSeen struct {
	// end is the highest sequence number after the data that the sender sent.
	end uint32
	// init tells that end holds a value.
	init bool
	// unacked tells that the sender sent data that the receiver did not
	// acknowledge yet.
	unacked bool
}

// tcpTrack is the Linux view of the state of a TCP connection. The stack
// still keeps the window state of the connection in tcpconntrack.TCB. That
// state decides whether a RST ends the connection.
type tcpTrack struct {
	// state is a ConntrackTCP* value.
	state uint8
	// simultaneousOpen tells that both ends sent a SYN.
	simultaneousOpen bool
	seen             [2]tcpSeen
	// retrans counts the repeats of the last ACK packet.
	retrans uint8
	// lastDir, lastSeq, lastAck, lastEnd, and lastWin describe the last ACK
	// packet, to find a repeat.
	lastDir uint8
	lastSeq uint32
	lastAck uint32
	lastEnd uint32
	lastWin uint16
}

// connProto is the state that the timeout of a connection needs.
type connProto struct {
	tcp tcpTrack
	// assured tells that traffic in both directions made the connection
	// unlikely to be a probe. An assured connection survives an early drop.
	assured bool
	// streamAt is the time after which a UDP flow with a reply counts as a
	// stream.
	streamAt tcpip.MonotonicTime
}

// udpStreamDelay is the time that a UDP flow with a reply stays unassured, as
// the two seconds in nf_conntrack_udp_packet.
const udpStreamDelay = 2 * time.Second

// tcpAfter reports whether a is after b in sequence space.
func tcpAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

// refreshLocked sets the expiry time of the connection to now plus timeout.
//
// +checklocks:cn.stateMu
func (cn *conn) refreshLocked(now tcpip.MonotonicTime, timeout time.Duration) {
	cn.lastUsed = now
	cn.timeout = timeout
}

// trackLocked moves the connection to the state that the packet causes and
// sets the timeout of the connection. The caller holds stateMu, has set
// replySeen for a packet of the reply direction, and has updated the TCB.
//
// +checklocks:cn.stateMu
func (cn *conn) trackLocked(pkt *PacketBuffer, reply bool, now tcpip.MonotonicTime) {
	cfg := cn.ct.config()
	switch pkt.TransportProtocolNumber {
	case header.TCPProtocolNumber:
		cn.trackTCPLocked(cfg, pkt, reply, now)
	case header.UDPProtocolNumber:
		cn.trackUDPLocked(cfg, now)
	case header.ICMPv4ProtocolNumber:
		cn.refreshLocked(now, cfg.timeouts[ConntrackTimeoutICMP])
	case header.ICMPv6ProtocolNumber:
		cn.refreshLocked(now, cfg.timeouts[ConntrackTimeoutICMPv6])
	default:
		cn.refreshLocked(now, cfg.timeouts[ConntrackTimeoutGeneric])
	}
}

// trackUDPLocked sets the timeout of a UDP flow. A flow without a reply uses
// the short timeout. A flow with a reply that is two seconds old uses the
// stream timeout and becomes assured.
//
// +checklocks:cn.stateMu
func (cn *conn) trackUDPLocked(cfg *conntrackConfig, now tcpip.MonotonicTime) {
	if !cn.replySeen {
		cn.refreshLocked(now, cfg.timeouts[ConntrackTimeoutUDP])
		return
	}
	timeout := cfg.timeouts[ConntrackTimeoutUDP]
	if now.After(cn.proto.streamAt) {
		timeout = cfg.timeouts[ConntrackTimeoutUDPStream]
		cn.proto.assured = true
	}
	cn.refreshLocked(now, timeout)
}

// trackTCPLocked is nf_conntrack_tcp_packet.
//
// +checklocks:cn.stateMu
func (cn *conn) trackTCPLocked(cfg *conntrackConfig, pkt *PacketBuffer, reply bool, now tcpip.MonotonicTime) {
	tr := &cn.proto.tcp
	hdr := header.TCP(pkt.TransportHeader().Slice())
	flags := hdr.Flags()
	dir := tcpDirOriginal
	if reply {
		dir = tcpDirReply
	}
	class := tcpClass(flags)
	old := tr.state
	next := tcpTransitions[dir][class][old]

	switch next {
	case tcpInvalid, tcpIgnore:
		return
	case sSS:
		// A SYN on a closed connection reopens the tuple. The caller replaced
		// that connection before this packet, so the state does not occur.
		if old >= sTW {
			return
		}
	case sS2:
		tr.simultaneousOpen = true
	case sSR:
		if reply && class == tcpAck && tr.simultaneousOpen {
			next = sES
		}
	case sCL:
		if class == tcpRst && !cn.rstEndsConnLocked(reply, old) {
			return
		}
	}

	cn.trackWindowLocked(hdr, pkt.Data().Size(), dir, class)
	tr.state = next

	timeouts := &cfg.timeouts
	timeout := timeouts[tcpStateTimeout[next]]
	switch {
	case tr.retrans >= cfg.tcpMaxRetrans && timeout > timeouts[ConntrackTimeoutTCPMaxRetrans]:
		timeout = timeouts[ConntrackTimeoutTCPMaxRetrans]
	case class == tcpRst:
		timeout = timeouts[ConntrackTimeoutTCPClose]
	case (tr.seen[0].unacked || tr.seen[1].unacked) && timeout > timeouts[ConntrackTimeoutTCPUnacknowledged]:
		timeout = timeouts[ConntrackTimeoutTCPUnacknowledged]
	case tr.lastWin == 0 && timeout > timeouts[ConntrackTimeoutTCPMaxRetrans]:
		timeout = timeouts[ConntrackTimeoutTCPMaxRetrans]
	}

	if !cn.replySeen {
		if flags&header.TCPFlagRst != 0 {
			// The only answer to the SYN is a RST: the connection never
			// existed, so Linux deletes it at once.
			cn.dying = true
			return
		}
		if class == tcpSyn && old == sSS {
			// A repeated SYN does not renew the timeout. A client that
			// reuses its port would keep the entry, and its NAT target,
			// alive for ever.
			return
		}
		// A connection that Linux picked up in mid-stream has no reply
		// yet. It must not get the long ESTABLISHED timeout.
		if next == sES && timeout > timeouts[ConntrackTimeoutTCPUnacknowledged] {
			timeout = timeouts[ConntrackTimeoutTCPUnacknowledged]
		}
	} else if !cn.proto.assured && (old == sSR || old == sES) && next == sES {
		cn.proto.assured = true
	}
	cn.refreshLocked(now, timeout)
}

// rstEndsConnLocked reports whether a RST closes the connection. The window
// state of the TCB decides: a RST outside the window leaves the connection
// open, as Linux does for a RST that fails the window check. A RST of the
// sender in SYN_SENT has no window yet, and Linux accepts it.
//
// +checklocks:cn.stateMu
func (cn *conn) rstEndsConnLocked(reply bool, old uint8) bool {
	if cn.tcb.State() == tcpconntrack.ResultReset {
		return true
	}
	return !reply && old == sSS
}

// trackWindowLocked records the data that the sender sent and the receiver
// acknowledged, and counts the repeats of an ACK packet. The timeout of the
// connection shrinks while data is unacknowledged and after repeats. This is
// the part of tcp_in_window of Linux that sets those two timeouts.
//
// +checklocks:cn.stateMu
func (cn *conn) trackWindowLocked(hdr header.TCP, dataLen, dir, class int) {
	tr := &cn.proto.tcp
	sender, receiver := &tr.seen[dir], &tr.seen[1-dir]
	flags := hdr.Flags()
	seq, win := hdr.SequenceNumber(), hdr.WindowSize()
	end := seq + uint32(dataLen)
	if flags&header.TCPFlagSyn != 0 {
		end++
	}
	if flags&header.TCPFlagFin != 0 {
		end++
	}
	ack := hdr.AckNumber()
	if flags&header.TCPFlagAck == 0 {
		ack = receiver.end
	}

	switch {
	case !sender.init:
		sender.init, sender.end = true, end
	case tcpAfter(end, sender.end):
		sender.end = end
		sender.unacked = true
	}
	if receiver.init && ack == receiver.end {
		receiver.unacked = false
	}

	if class != tcpAck {
		return
	}
	if uint8(dir) == tr.lastDir && tr.lastSeq == seq && tr.lastAck == ack && tr.lastEnd == end && tr.lastWin == win {
		tr.retrans++
		return
	}
	tr.lastDir, tr.lastSeq, tr.lastAck, tr.lastEnd, tr.lastWin = uint8(dir), seq, ack, end, win
	tr.retrans = 0
}
