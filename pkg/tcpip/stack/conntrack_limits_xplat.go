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

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// This file holds the knobs of the connection tracker that Linux exposes
// through /proc/sys/net/netfilter: the timeout of each connection state and
// the limit on the number of connections. A network namespace owns the
// timeouts. The limit nf_conntrack_max is one value for the whole kernel, as
// on Linux, so the stacks of a kernel share one ConntrackLimit.
//
// Ref: net/netfilter/nf_conntrack_standalone.c (sysctl table),
// net/netfilter/nf_conntrack_proto_tcp.c (tcp_timeouts),
// net/netfilter/nf_conntrack_proto_udp.c (udp_timeouts), and
// net/netfilter/nf_conntrack_core.c (early_drop).

// ConntrackTimeout names one timeout of the connection tracker. Each value
// except the last one that no sysctl names has the Linux sysctl of the same
// name in its comment.
type ConntrackTimeout int

const (
	// ConntrackTimeoutGeneric is nf_conntrack_generic_timeout.
	ConntrackTimeoutGeneric ConntrackTimeout = iota
	// ConntrackTimeoutTCPSynSent is nf_conntrack_tcp_timeout_syn_sent.
	ConntrackTimeoutTCPSynSent
	// ConntrackTimeoutTCPSynRecv is nf_conntrack_tcp_timeout_syn_recv.
	ConntrackTimeoutTCPSynRecv
	// ConntrackTimeoutTCPEstablished is nf_conntrack_tcp_timeout_established.
	ConntrackTimeoutTCPEstablished
	// ConntrackTimeoutTCPFinWait is nf_conntrack_tcp_timeout_fin_wait.
	ConntrackTimeoutTCPFinWait
	// ConntrackTimeoutTCPCloseWait is nf_conntrack_tcp_timeout_close_wait.
	ConntrackTimeoutTCPCloseWait
	// ConntrackTimeoutTCPLastAck is nf_conntrack_tcp_timeout_last_ack.
	ConntrackTimeoutTCPLastAck
	// ConntrackTimeoutTCPTimeWait is nf_conntrack_tcp_timeout_time_wait.
	ConntrackTimeoutTCPTimeWait
	// ConntrackTimeoutTCPClose is nf_conntrack_tcp_timeout_close.
	ConntrackTimeoutTCPClose
	// ConntrackTimeoutTCPMaxRetrans is nf_conntrack_tcp_timeout_max_retrans.
	ConntrackTimeoutTCPMaxRetrans
	// ConntrackTimeoutTCPUnacknowledged is
	// nf_conntrack_tcp_timeout_unacknowledged.
	ConntrackTimeoutTCPUnacknowledged
	// ConntrackTimeoutUDP is nf_conntrack_udp_timeout, the timeout of a UDP
	// flow that has no reply.
	ConntrackTimeoutUDP
	// ConntrackTimeoutUDPStream is nf_conntrack_udp_timeout_stream, the
	// timeout of a UDP flow that has traffic in both directions.
	ConntrackTimeoutUDPStream
	// ConntrackTimeoutICMP is nf_conntrack_icmp_timeout.
	ConntrackTimeoutICMP
	// ConntrackTimeoutICMPv6 is nf_conntrack_icmpv6_timeout.
	ConntrackTimeoutICMPv6

	// conntrackTimeoutTCPSynSent2 is the timeout of a TCP simultaneous open.
	// Linux sets it only through a cttimeout policy, so no sysctl names it.
	conntrackTimeoutTCPSynSent2

	numConntrackTimeouts
)

// DefaultConntrackMax is the initial value of nf_conntrack_max. Linux sets
// the value from the memory size: 262144 for a host of more than 4 GiB.
const DefaultConntrackMax = 262144

// defaultConntrackTimeouts holds the initial timeouts, which are the defaults
// of Linux.
var defaultConntrackTimeouts = [numConntrackTimeouts]time.Duration{
	ConntrackTimeoutGeneric:           600 * time.Second,
	ConntrackTimeoutTCPSynSent:        2 * time.Minute,
	ConntrackTimeoutTCPSynRecv:        60 * time.Second,
	ConntrackTimeoutTCPEstablished:    5 * 24 * time.Hour,
	ConntrackTimeoutTCPFinWait:        2 * time.Minute,
	ConntrackTimeoutTCPCloseWait:      60 * time.Second,
	ConntrackTimeoutTCPLastAck:        30 * time.Second,
	ConntrackTimeoutTCPTimeWait:       2 * time.Minute,
	ConntrackTimeoutTCPClose:          10 * time.Second,
	ConntrackTimeoutTCPMaxRetrans:     5 * time.Minute,
	ConntrackTimeoutTCPUnacknowledged: 5 * time.Minute,
	ConntrackTimeoutUDP:               30 * time.Second,
	ConntrackTimeoutUDPStream:         120 * time.Second,
	ConntrackTimeoutICMP:              30 * time.Second,
	ConntrackTimeoutICMPv6:            30 * time.Second,
	conntrackTimeoutTCPSynSent2:       2 * time.Minute,
}

// defaultConntrackTCPMaxRetrans is the initial value of
// nf_conntrack_tcp_max_retrans.
const defaultConntrackTCPMaxRetrans = 3

// DefaultConntrackTimeout returns the Linux default of the timeout.
func DefaultConntrackTimeout(t ConntrackTimeout) time.Duration {
	return defaultConntrackTimeouts[t]
}

// conntrackConfig is an immutable set of timeouts. A change builds a new set,
// so a packet reads one consistent set without a lock.
//
// +stateify savable
type conntrackConfig struct {
	timeouts      [numConntrackTimeouts]time.Duration
	tcpMaxRetrans uint8
}

var defaultConntrackConfig = conntrackConfig{
	timeouts:      defaultConntrackTimeouts,
	tcpMaxRetrans: defaultConntrackTCPMaxRetrans,
}

// config returns the timeouts of the table. A table that no write changed has
// the Linux defaults.
func (ct *ConnTrack) config() *conntrackConfig {
	if c := ct.cfg.Load(); c != nil {
		return c
	}
	return &defaultConntrackConfig
}

// updateConfig replaces the timeouts with the result of change.
func (ct *ConnTrack) updateConfig(change func(*conntrackConfig)) {
	for {
		old := ct.cfg.Load()
		next := defaultConntrackConfig
		if old != nil {
			next = *old
		}
		change(&next)
		if ct.cfg.CompareAndSwap(old, &next) {
			return
		}
	}
}

// ConntrackLimit is the limit nf_conntrack_max. Linux keeps one limit for all
// network namespaces, so the stacks of one kernel share one ConntrackLimit.
//
// +stateify savable
type ConntrackLimit struct {
	max atomicbitops.Uint32
}

// NewConntrackLimit returns a limit with the value max. The value 0 means no
// limit.
func NewConntrackLimit(max uint32) *ConntrackLimit {
	l := &ConntrackLimit{}
	l.max.Store(max)
	return l
}

// Max returns the limit. The value 0 means no limit. Linux stores the value as
// an unsigned integer, so a value that a guest writes as a negative integer is
// a very large limit.
func (l *ConntrackLimit) Max() uint32 {
	return l.max.Load()
}

// SetMax sets the limit.
func (l *ConntrackLimit) SetMax(max uint32) {
	l.max.Store(max)
}

// maxEntries returns the limit on the connections of the table, or 0 for no
// limit.
func (ct *ConnTrack) maxEntries() uint32 {
	if l := ct.limit.Load(); l != nil {
		return l.Max()
	}
	return 0
}

// ConntrackTimeout returns the timeout of the stack.
func (s *Stack) ConntrackTimeout(t ConntrackTimeout) time.Duration {
	return s.tables.connections.config().timeouts[t]
}

// SetConntrackTimeout sets the timeout of the stack. A connection that exists
// keeps the timeout of its last packet, as on Linux. The next packet of the
// connection uses the new value.
func (s *Stack) SetConntrackTimeout(t ConntrackTimeout, d time.Duration) {
	s.tables.connections.updateConfig(func(c *conntrackConfig) { c.timeouts[t] = d })
}

// ConntrackTCPMaxRetrans returns nf_conntrack_tcp_max_retrans.
func (s *Stack) ConntrackTCPMaxRetrans() uint8 {
	return s.tables.connections.config().tcpMaxRetrans
}

// SetConntrackTCPMaxRetrans sets nf_conntrack_tcp_max_retrans.
func (s *Stack) SetConntrackTCPMaxRetrans(n uint8) {
	s.tables.connections.updateConfig(func(c *conntrackConfig) { c.tcpMaxRetrans = n })
}

// ConntrackLimit returns the limit that the stack obeys, or nil when the stack
// has no limit.
func (s *Stack) ConntrackLimit() *ConntrackLimit {
	return s.tables.connections.limit.Load()
}

// SetConntrackLimit sets the limit that the stack obeys. A nil limit removes
// the limit.
func (s *Stack) SetConntrackLimit(l *ConntrackLimit) {
	s.tables.connections.limit.Store(l)
}

// ConntrackCount returns nf_conntrack_count: the number of connections in the
// table of the stack, including the connections that timed out and that the
// reaper has not removed yet.
func (s *Stack) ConntrackCount() int {
	return int(s.tables.connections.count.Load())
}

// ConntrackBucketCount is the number of hash buckets of a connection table.
const ConntrackBucketCount = numBuckets

// ConntrackBuckets returns nf_conntrack_buckets, the number of hash buckets of
// the table.
func (s *Stack) ConntrackBuckets() int {
	return ConntrackBucketCount
}

// conntrackEvictionRange is the number of buckets that an early drop reads, as
// NF_CT_EVICTION_RANGE of Linux.
const conntrackEvictionRange = 8

// tableFullLog reports a table that dropped a packet. Linux warns
// "nf_conntrack: table full, dropping packet" with a rate limit.
var tableFullLog = log.BasicRateLimitedLogger(time.Minute)

// initialTimeout returns the timeout of a connection until its first packet
// refreshes it. A lookup that runs before the refresh must not see the
// connection as timed out.
func initialTimeout(cfg *conntrackConfig, transProto tcpip.TransportProtocolNumber) time.Duration {
	switch transProto {
	case header.TCPProtocolNumber:
		return cfg.timeouts[ConntrackTimeoutTCPSynSent]
	case header.UDPProtocolNumber:
		return cfg.timeouts[ConntrackTimeoutUDP]
	case header.ICMPv4ProtocolNumber:
		return cfg.timeouts[ConntrackTimeoutICMP]
	case header.ICMPv6ProtocolNumber:
		return cfg.timeouts[ConntrackTimeoutICMPv6]
	}
	return cfg.timeouts[ConntrackTimeoutGeneric]
}

// reserve counts a new connection against nf_conntrack_max, as
// __nf_conntrack_alloc does. When the count passes the limit, it removes a
// connection that is not assured or has timed out. It returns false when no
// connection can leave: the caller drops the packet.
func (ct *ConnTrack) reserve(hashBucket int, now tcpip.MonotonicTime) bool {
	n := ct.count.Add(1)
	if max := ct.maxEntries(); max != 0 && uint32(n) > max {
		if !ct.earlyDrop(hashBucket, now) {
			ct.count.Add(-1)
			tableFullLog.Warningf("nf_conntrack: table full, dropping packet")
			return false
		}
	}
	return true
}

// release gives the place of a removed connection back to the count. The
// caller removed the tuples of the connection from the table. A connection
// gives back its place once.
func (ct *ConnTrack) release(cn *conn) {
	if cn.released.CompareAndSwap(0, 1) {
		ct.count.Add(-1)
	}
}

// earlyDrop is early_drop of Linux. It reads the buckets from the bucket of
// the new connection, up to the eviction range. It removes the confirmed
// connections of the first bucket that has connections to remove: those that
// timed out, and those that are not assured. It reports whether it removed one.
func (ct *ConnTrack) earlyDrop(start int, now tcpip.MonotonicTime) bool {
	buckets := ct.tableBuckets()
	for i := range conntrackEvictionRange {
		removed := false
		for _, cn := range buckets[(start+i)%len(buckets)].evictable(now) {
			if ct.removeConn(cn) {
				removed = true
			}
		}
		if removed {
			return true
		}
	}
	return false
}

// evictable returns the confirmed connections of the bucket that an early drop
// may remove. An assured connection stays unless it timed out.
func (bkt *bucket) evictable(now tcpip.MonotonicTime) []*conn {
	var conns []*conn
	bkt.mu.RLock()
	defer bkt.mu.RUnlock()
	for t := bkt.tuples.Front(); t != nil; t = t.Next() {
		cn := t.conn
		if cn.getFinalizeResult() != finalizeResultSuccess {
			continue
		}
		if cn.timedOut(now) || !cn.assured() {
			conns = append(conns, cn)
		}
	}
	return conns
}

// assured reports whether the connection is assured.
func (cn *conn) assured() bool {
	cn.stateMu.RLock()
	defer cn.stateMu.RUnlock()
	return cn.proto.assured
}

// removeConn removes both tuples of a confirmed connection from the table. It
// takes the two bucket locks in the order of the buckets, as the reaper does.
// It reports false when the table already removed the connection.
func (ct *ConnTrack) removeConn(cn *conn) bool {
	buckets := ct.tableBuckets()
	cn.mu.RLock()
	replyID := cn.reply.tupleID
	cn.mu.RUnlock()
	orig := ct.bucketWithTableLength(cn.original.tupleID, len(buckets))
	repl := ct.bucketWithTableLength(replyID, len(buckets))
	lo, hi := min(orig, repl), max(orig, repl)

	buckets[lo].mu.Lock()
	defer buckets[lo].mu.Unlock()
	if hi != lo {
		buckets[hi].mu.NestedLock(bucketLockOthertuple)
		defer buckets[hi].mu.NestedUnlock(bucketLockOthertuple)
	}
	if cn.released.Load() != 0 {
		return false
	}
	buckets[orig].tuples.Remove(&cn.original) // +checklocksforce: orig is lo or hi, and this function holds both locks
	// A connection that has the same original and reply tuple has no tuple
	// of the reply in the table. See finalize.
	if cn.original.tupleID != replyID {
		buckets[repl].tuples.Remove(&cn.reply) // +checklocksforce: repl is lo or hi, and this function holds both locks
	}
	ct.release(cn)
	return true
}

// dropUnconfirmed ends the connection of a packet that a hook drops, and it
// returns false so that the hook can return it. A connection that no packet has
// confirmed lives only for that packet. Linux frees it when it frees the
// packet, so a flood of dropped packets cannot fill nf_conntrack_max. A
// confirmed connection stays, because a dropped packet does not end it.
func (ct *ConnTrack) dropUnconfirmed(pkt *PacketBuffer) bool {
	if t := pkt.tuple; t != nil {
		pkt.tuple = nil
		ct.discardUnconfirmed(t.conn)
	}
	return false
}

// discardUnconfirmed removes the original tuple of a connection that was not
// finalized and gives its place back to the count. It does nothing when the
// connection was finalized or discarded. A later packet that holds the
// connection fails to finalize it, as it does after a tuple conflict.
func (ct *ConnTrack) discardUnconfirmed(cn *conn) {
	cn.finalizeOnce.Do(func() {
		if cn.getFinalizeResult() != 0 {
			return
		}
		cn.finalizeResult.Store(uint32(finalizeResultConflict))
		buckets := ct.tableBuckets()
		bkt := &buckets[ct.bucketWithTableLength(cn.original.tupleID, len(buckets))]
		bkt.mu.Lock()
		// The reaper may have removed an unconfirmed connection that timed
		// out. It removes the tuple and releases the place under this lock.
		if cn.released.Load() == 0 {
			bkt.tuples.Remove(&cn.original)
			ct.release(cn)
		}
		bkt.mu.Unlock()
	})
}
