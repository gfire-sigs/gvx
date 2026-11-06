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
	// ConntrackTCPSynSent2 is the state after the SYN of the reply direction
	// of a simultaneous open.
	ConntrackTCPSynSent2
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
	// Mark is the connection mark, as the CONNMARK target sets it.
	Mark uint32
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
	lastUsed, timeout, dying := cn.lastUsed, cn.timeout, cn.dying
	replySeen, assured, tcpState := cn.replySeen, cn.proto.assured, cn.proto.tcp.state
	cn.stateMu.RUnlock()

	e := ConntrackEntry{
		ID:       tupleHash(cn.original.tupleID, cn.ct.nftIDSeed),
		Original: tupleOfID(cn.original.tupleID),
		Reply:    tupleOfID(replyID),
		Status:   ConntrackStatusConfirmed,
		Mark:     cn.mark.Load(),
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

	if e.Original.TransProto == header.TCPProtocolNumber {
		e.HasTCPState = true
		e.TCPState = tcpState
	}
	if assured {
		e.Status |= ConntrackStatusAssured
	}
	if left := lastUsed.Add(timeout).Sub(now); left > 0 && !dying {
		e.Timeout = left
	}
	return e
}

// expire makes the connection invisible to lookups and lets the reaper remove
// it. The next packet of the flow then starts a new connection, which runs the
// NAT rules again. A packet that already holds the connection keeps it, but
// the packet does not renew the timeout.
func (cn *conn) expire() {
	cn.stateMu.Lock()
	defer cn.stateMu.Unlock()
	cn.dying = true
}

// forEachConfirmedInBucket calls visit for each connection whose original
// tuple is in the bucket, that has both tuples in the table, and that has not
// expired. It stops when visit returns false and then reports false. visit
// holds the lock of the bucket, so it must not call the connection table.
func (bkt *bucket) forEachConfirmedInBucket(now tcpip.MonotonicTime, visit func(cn *conn, now tcpip.MonotonicTime) bool) bool {
	bkt.mu.RLock()
	defer bkt.mu.RUnlock()
	for t := bkt.tuples.Front(); t != nil; t = t.Next() {
		cn := t.conn
		if t.reply || cn.getFinalizeResult() != finalizeResultSuccess || cn.timedOut(now) {
			continue
		}
		if !visit(cn, now) {
			return false
		}
	}
	return true
}

// tableBuckets returns the bucket slice. Only a restore changes the slice, so
// the caller can use it without the lock of the table.
func (ct *ConnTrack) tableBuckets() []bucket {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.buckets
}

// forEachConfirmed calls visit for each connection that has both tuples in the
// table and has not expired. It stops when visit returns false. visit holds a
// lock of the table, so it must not call the connection table.
func (ct *ConnTrack) forEachConfirmed(visit func(cn *conn, now tcpip.MonotonicTime) bool) {
	buckets := ct.tableBuckets()
	now := ct.clock.NowMonotonic()
	for i := range buckets {
		if !buckets[i].forEachConfirmedInBucket(now, visit) {
			return
		}
	}
}

// confirmedForTuple returns the connection that owns the tuple in either
// direction. It looks in the one bucket that the hash of the tuple selects. It
// returns nil when no confirmed connection owns the tuple.
func (ct *ConnTrack) confirmedForTuple(t ConntrackTuple) *conn {
	tup := ct.connForTID(tupleID{
		srcAddr:                   t.Src,
		srcPortOrEchoRequestIdent: t.SrcPort,
		dstAddr:                   t.Dst,
		dstPortOrEchoReplyIdent:   t.DstPort,
		transProto:                t.TransProto,
		netProto:                  t.NetProto,
	})
	if tup == nil || tup.conn.getFinalizeResult() != finalizeResultSuccess {
		return nil
	}
	return tup.conn
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

// ConntrackScan reads the connection table one bucket at a time. Each call
// appends to dst a snapshot of each confirmed connection in the next bucket.
// It reports false when the call read the last bucket, and then it returns no
// entry on any later call. A ConntrackScan is for one goroutine at a time.
type ConntrackScan func(dst []ConntrackEntry) (entries []ConntrackEntry, more bool)

// ConntrackScanner starts a scan of the connection table at its first bucket.
// A connection belongs to the bucket of its original tuple for its whole life.
// A connection that exists from the start of a scan to its end therefore
// appears in the result of the scan, however the table changes in between.
func (s *Stack) ConntrackScanner() ConntrackScan {
	ct := &s.tables.connections
	buckets := ct.tableBuckets()
	next := 0
	return func(dst []ConntrackEntry) ([]ConntrackEntry, bool) {
		if next >= len(buckets) {
			return dst, false
		}
		buckets[next].forEachConfirmedInBucket(ct.clock.NowMonotonic(), func(cn *conn, now tcpip.MonotonicTime) bool {
			dst = append(dst, cn.snapshot(now))
			return true
		})
		next++
		return dst, next < len(buckets)
	}
}

// ConntrackLookup returns the connection that owns the tuple in either
// direction. It reports false when no confirmed connection owns it.
func (s *Stack) ConntrackLookup(t ConntrackTuple) (ConntrackEntry, bool) {
	cn := s.tables.connections.confirmedForTuple(t)
	if cn == nil {
		return ConntrackEntry{}, false
	}
	return cn.snapshot(s.tables.connections.clock.NowMonotonic()), true
}

// ConntrackDeleteTuple expires the connection that owns the tuple in either
// direction when accept returns true for its snapshot. A nil accept accepts
// every connection. It returns the snapshot and reports whether the
// connection exists and was expired.
func (s *Stack) ConntrackDeleteTuple(t ConntrackTuple, accept func(ConntrackEntry) bool) (ConntrackEntry, bool) {
	ct := &s.tables.connections
	cn := ct.confirmedForTuple(t)
	if cn == nil {
		return ConntrackEntry{}, false
	}
	now := ct.clock.NowMonotonic()
	e := cn.snapshot(now)
	if accept != nil && !accept(e) {
		return e, false
	}
	cn.expire()
	return e, true
}

// ConntrackDelete expires every confirmed connection for which match returns
// true and returns their number. match gets a snapshot of the connection.
func (s *Stack) ConntrackDelete(match func(ConntrackEntry) bool) int {
	deleted := 0
	s.tables.connections.forEachConfirmed(func(cn *conn, now tcpip.MonotonicTime) bool {
		if match(cn.snapshot(now)) {
			cn.expire()
			deleted++
		}
		return true
	})
	return deleted
}

// closedTCP reports whether the TCP state of the connection is TIME_WAIT or
// CLOSE: both streams sent a FIN, or one side sent a RST.
func (cn *conn) closedTCP() bool {
	cn.stateMu.RLock()
	defer cn.stateMu.RUnlock()
	return cn.proto.tcp.state == ConntrackTCPTimeWait || cn.proto.tcp.state == ConntrackTCPClose
}

// expireClosedOnSYN lets a SYN reopen a closed TCP tuple. The state machine of
// Linux (nf_conntrack_proto_tcp) treats a SYN on a connection in TIME_WAIT or
// CLOSE as the start of a new connection: it destroys the old entry, and the
// packet creates an entry that runs the NAT rules again. Without this, a new
// connection with the same five values keeps the NAT target of the old one
// until the entry times out. A SYN with another flag set, such as the SYN-ACK
// of a reply, never reopens a tuple.
func (ct *ConnTrack) expireClosedOnSYN(pkt *PacketBuffer, tid tupleID, bkt *bucket, now tcpip.MonotonicTime) {
	// An ICMP error about a TCP connection has the tuple of that connection but
	// carries no TCP header of its own.
	if pkt.TransportProtocolNumber != header.TCPProtocolNumber {
		return
	}
	tcpHeader := header.TCP(pkt.TransportHeader().Slice())
	const flags = header.TCPFlagSyn | header.TCPFlagAck | header.TCPFlagRst | header.TCPFlagFin
	if len(tcpHeader) < header.TCPMinimumSize || tcpHeader.Flags()&flags != header.TCPFlagSyn {
		return
	}
	if t := bkt.connForTID(tid, now); t != nil && t.conn.closedTCP() {
		t.conn.expire()
	}
}

// ConnMark returns the connection mark of the connection of the packet. A
// packet without a tracked connection has the mark 0.
func (pk *PacketBuffer) ConnMark() uint32 {
	if !pk.IsConnTrackConfigured() {
		return 0
	}
	return pk.tuple.conn.mark.Load()
}

// SetConnMark sets the connection mark of the connection of the packet. It
// does nothing for a packet without a tracked connection.
func (pk *PacketBuffer) SetConnMark(mark uint32) {
	if !pk.IsConnTrackConfigured() {
		return
	}
	pk.tuple.conn.mark.Store(mark)
}

// UpdateConnMark replaces the connection mark of the connection of the packet
// with update(old) and returns the new mark. The update is atomic: two
// packets of one connection never lose each other's change. It returns 0 and
// does nothing for a packet without a tracked connection.
func (pk *PacketBuffer) UpdateConnMark(update func(old uint32) uint32) uint32 {
	if !pk.IsConnTrackConfigured() {
		return 0
	}
	mark := &pk.tuple.conn.mark
	for {
		old := mark.Load()
		next := update(old)
		if mark.CompareAndSwap(old, next) {
			return next
		}
	}
}
