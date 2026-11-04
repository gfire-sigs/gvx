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

// This file gives ctnetlink access to the connection table. A caller reads a
// snapshot of each tracked connection and deletes connections. It never holds
// a reference to the table internals.
//
// Ref: include/uapi/linux/netfilter/nf_conntrack_common.h (IPS_*) and
// include/uapi/linux/netfilter/nf_conntrack_tcp.h (TCP_CONNTRACK_*).

// Bits of ConntrackEntry.Status. The values are the IPS_* bits of Linux.
const (
	ConntrackStatusSeenReply  uint32 = 1 << 1
	ConntrackStatusAssured    uint32 = 1 << 2
	ConntrackStatusConfirmed  uint32 = 1 << 3
	ConntrackStatusSrcNAT     uint32 = 1 << 4
	ConntrackStatusDstNAT     uint32 = 1 << 5
	ConntrackStatusSrcNATDone uint32 = 1 << 7
	ConntrackStatusDstNATDone uint32 = 1 << 8
)

// TCP states of ConntrackEntry.TCPState. The values are the TCP_CONNTRACK_*
// values of Linux.
const (
	ConntrackTCPNone uint8 = iota
	ConntrackTCPSynSent
	ConntrackTCPSynRecv
	ConntrackTCPEstablished
	ConntrackTCPFinWait
	ConntrackTCPCloseWait
	ConntrackTCPLastAck
	ConntrackTCPTimeWait
	ConntrackTCPClose
)

// ConntrackTuple is one direction of a tracked connection. For ICMP echo, the
// identifier is SrcPort in the original tuple and DstPort in the reply tuple.
type ConntrackTuple struct {
	NetProto   tcpip.NetworkProtocolNumber
	TransProto tcpip.TransportProtocolNumber
	Src        tcpip.Address
	Dst        tcpip.Address
	SrcPort    uint16
	DstPort    uint16
}

// ConntrackEntry is a snapshot of one confirmed connection.
type ConntrackEntry struct {
	// ID identifies the connection. It stays the same while the connection lives.
	ID       uint32
	Original ConntrackTuple
	Reply    ConntrackTuple
	// Status holds ConntrackStatus* bits.
	Status uint32
	// Timeout is the time until the entry expires.
	Timeout time.Duration
	// HasTCPState is true for a TCP connection. TCPState then holds a
	// ConntrackTCP* value.
	HasTCPState bool
	TCPState    uint8
}

func tupleOfID(id tupleID) ConntrackTuple {
	return ConntrackTuple{
		NetProto:   id.netProto,
		TransProto: id.transProto,
		Src:        id.srcAddr,
		Dst:        id.dstAddr,
		SrcPort:    id.srcPortOrEchoRequestIdent,
		DstPort:    id.dstPortOrEchoReplyIdent,
	}
}

// snapshot returns the state of the connection.
func (cn *conn) snapshot(now tcpip.MonotonicTime) ConntrackEntry {
	cn.mu.RLock()
	replyID := cn.reply.tupleID
	sourceManip, destinationManip := cn.sourceManip, cn.destinationManip
	cn.mu.RUnlock()

	cn.stateMu.RLock()
	lastUsed, replySeen := cn.lastUsed, cn.replySeen
	tcbState := cn.tcb.State()
	cn.stateMu.RUnlock()

	e := ConntrackEntry{
		ID:       tupleHash(cn.original.tupleID, cn.ct.nftIDSeed),
		Original: tupleOfID(cn.original.tupleID),
		Reply:    tupleOfID(replyID),
		Status:   ConntrackStatusConfirmed,
	}
	if replySeen {
		e.Status |= ConntrackStatusSeenReply
	}
	if sourceManip == manipPerformed {
		e.Status |= ConntrackStatusSrcNAT
	}
	if destinationManip == manipPerformed {
		e.Status |= ConntrackStatusDstNAT
	}
	if sourceManip != manipNotPerformed {
		e.Status |= ConntrackStatusSrcNATDone
	}
	if destinationManip != manipNotPerformed {
		e.Status |= ConntrackStatusDstNATDone
	}

	timeout := unestablishedTimeout
	if e.Original.TransProto == header.TCPProtocolNumber {
		e.HasTCPState = true
		switch tcbState {
		case tcpconntrack.ResultConnecting:
			e.TCPState = ConntrackTCPSynSent
			if replySeen {
				e.TCPState = ConntrackTCPSynRecv
			}
		case tcpconntrack.ResultAlive:
			e.TCPState = ConntrackTCPEstablished
			e.Status |= ConntrackStatusAssured
			timeout = establishedTimeout
		case tcpconntrack.ResultClosedByOriginator, tcpconntrack.ResultClosedByResponder:
			e.TCPState = ConntrackTCPTimeWait
			e.Status |= ConntrackStatusAssured
		case tcpconntrack.ResultReset:
			e.TCPState = ConntrackTCPClose
		default:
			e.TCPState = ConntrackTCPNone
		}
	} else if replySeen {
		e.Status |= ConntrackStatusAssured
	}
	if left := timeout - now.Sub(lastUsed); left > 0 {
		e.Timeout = left
	}
	return e
}

// expire makes the connection invisible to lookups and lets the reaper remove
// it. The next packet of the flow then starts a new connection, which runs the
// NAT rules again. A packet that already holds the connection keeps it.
func (cn *conn) expire(now tcpip.MonotonicTime) {
	cn.stateMu.Lock()
	defer cn.stateMu.Unlock()
	cn.lastUsed = now.Add(-(establishedTimeout + unestablishedTimeout + time.Second))
}

// forEachConfirmed calls visit for each connection that has both tuples in the
// table and has not expired. It stops when visit returns false. visit holds a
// lock of the table, so it must not call the connection table.
func (ct *ConnTrack) forEachConfirmed(visit func(cn *conn, now tcpip.MonotonicTime) bool) {
	ct.mu.RLock()
	buckets := ct.buckets
	ct.mu.RUnlock()
	now := ct.clock.NowMonotonic()
	for i := range buckets {
		bkt := &buckets[i]
		bkt.mu.RLock()
		for t := bkt.tuples.Front(); t != nil; t = t.Next() {
			cn := t.conn
			if t.reply || cn.getFinalizeResult() != finalizeResultSuccess || cn.timedOut(now) {
				continue
			}
			if !visit(cn, now) {
				bkt.mu.RUnlock()
				return
			}
		}
		bkt.mu.RUnlock()
	}
}

// ConntrackEntries returns a snapshot of every confirmed connection of the
// stack, in no particular order.
func (s *Stack) ConntrackEntries() []ConntrackEntry {
	var entries []ConntrackEntry
	s.tables.connections.forEachConfirmed(func(cn *conn, now tcpip.MonotonicTime) bool {
		entries = append(entries, cn.snapshot(now))
		return true
	})
	return entries
}

// ConntrackLookup returns the connection that owns the tuple in either
// direction. It reports false when no confirmed connection owns it.
func (s *Stack) ConntrackLookup(t ConntrackTuple) (ConntrackEntry, bool) {
	var found ConntrackEntry
	var ok bool
	s.tables.connections.forEachConfirmed(func(cn *conn, now tcpip.MonotonicTime) bool {
		e := cn.snapshot(now)
		if e.Original == t || e.Reply == t {
			found, ok = e, true
			return false
		}
		return true
	})
	return found, ok
}

// ConntrackDelete expires every confirmed connection for which match returns
// true and returns their number. match gets a snapshot of the connection.
func (s *Stack) ConntrackDelete(match func(ConntrackEntry) bool) int {
	deleted := 0
	s.tables.connections.forEachConfirmed(func(cn *conn, now tcpip.MonotonicTime) bool {
		if match(cn.snapshot(now)) {
			cn.expire(now)
			deleted++
		}
		return true
	})
	return deleted
}
