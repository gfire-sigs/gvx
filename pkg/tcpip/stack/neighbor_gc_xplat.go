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

	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// This file limits the dynamic entries of the neighbor tables as neigh_alloc and
// neigh_forced_gc of net/core/neighbour.c do in Linux. Linux counts the entries
// of one table (arp_tbl or nd_tbl) over all links, and the sysctls
// net.ipv4.neigh.default.gc_thresh1 to gc_thresh3 and the IPv6 equivalents
// set the thresholds. A static entry (NUD_PERMANENT) is not on the garbage
// collection list, so it does not count and has no limit.

// Defaults of gc_thresh1, gc_thresh2, and gc_thresh3 in arp_tbl and nd_tbl.
const (
	DefaultNeighborGCThresh1 = 128
	DefaultNeighborGCThresh2 = 512
	DefaultNeighborGCThresh3 = 1024
)

const (
	// neighborGCRecent is the age below which a stale entry survives a forced
	// collection. Linux uses 5 * HZ.
	neighborGCRecent = 5 * time.Second
	// neighborGCBudget is the time that a forced collection may run before it
	// stops. Linux stops after one millisecond.
	neighborGCBudget = time.Millisecond
	// neighborGCBudgetStep is the count of removal candidates between two clock
	// reads of a forced collection.
	neighborGCBudgetStep = 16
)

// NeighborGCThresholds are gc_thresh1, gc_thresh2, and gc_thresh3 of a
// neighbor table. Linux accepts every value from 0 to MaxInt32 and does not
// compare the thresholds with each other.
type NeighborGCThresholds struct {
	Thresh1, Thresh2, Thresh3 int32
}

// DefaultNeighborGCThresholds returns the thresholds of a new neighbor table.
func DefaultNeighborGCThresholds() NeighborGCThresholds {
	return NeighborGCThresholds{DefaultNeighborGCThresh1, DefaultNeighborGCThresh2, DefaultNeighborGCThresh3}
}

// neighborTable is the neighbor table of one network protocol in a stack. It
// corresponds to struct neigh_table of Linux for the network namespace of the
// stack. It owns the thresholds and the registry of the caches of the links.
type neighborTable struct {
	// allocMu orders the allocation of dynamic entries and the forced
	// collection. It plays the role of tbl->lock for neigh_alloc. The code
	// takes allocMu before the lock of a cache and never the reverse.
	allocMu sync.Mutex
	// thresholds and lastFlush are protected by allocMu.
	thresholds *NeighborGCThresholds
	lastFlush  tcpip.MonotonicTime

	// regMu protects caches. It is a leaf lock.
	regMu  sync.Mutex
	caches []*neighborCache
}

// neighborTables are the neighbor tables of the stack.
type neighborTables struct {
	ipv4, ipv6 neighborTable
}

// of returns the table of the network protocol, or nil when the protocol has
// no neighbor table.
func (t *neighborTables) of(protocol tcpip.NetworkProtocolNumber) *neighborTable {
	switch protocol {
	case header.IPv4ProtocolNumber:
		return &t.ipv4
	case header.IPv6ProtocolNumber:
		return &t.ipv6
	}
	return nil
}

// NeighborGCThresholds returns gc_thresh1, gc_thresh2, and gc_thresh3 of the
// neighbor table of the protocol.
func (s *Stack) NeighborGCThresholds(protocol tcpip.NetworkProtocolNumber) (NeighborGCThresholds, tcpip.Error) {
	t := s.neighborTables.of(protocol)
	if t == nil {
		return NeighborGCThresholds{}, &tcpip.ErrNotSupported{}
	}
	t.allocMu.Lock()
	defer t.allocMu.Unlock()
	return t.thresholdsLocked(), nil
}

// SetNeighborGCThresholds sets gc_thresh1, gc_thresh2, and gc_thresh3 of the
// neighbor table of the protocol. A table that already holds more entries than
// the new threshold keeps them. The next new dynamic entry starts a collection.
func (s *Stack) SetNeighborGCThresholds(protocol tcpip.NetworkProtocolNumber, th NeighborGCThresholds) tcpip.Error {
	t := s.neighborTables.of(protocol)
	if t == nil {
		return &tcpip.ErrNotSupported{}
	}
	t.allocMu.Lock()
	defer t.allocMu.Unlock()
	t.thresholds = &th
	return nil
}

func (t *neighborTable) thresholdsLocked() NeighborGCThresholds {
	if t.thresholds == nil {
		return DefaultNeighborGCThresholds()
	}
	return *t.thresholds
}

// register adds the cache of a link to the table. It does nothing when the
// cache is in the table.
func (t *neighborTable) register(n *neighborCache) {
	t.regMu.Lock()
	defer t.regMu.Unlock()
	for _, c := range t.caches {
		if c == n {
			return
		}
	}
	t.caches = append(t.caches, n)
}

// unregister removes the cache of a link from the table. The entries of the
// cache stop counting.
func (t *neighborTable) unregister(n *neighborCache) {
	t.regMu.Lock()
	defer t.regMu.Unlock()
	for i, c := range t.caches {
		if c == n {
			t.caches = append(t.caches[:i], t.caches[i+1:]...)
			return
		}
	}
}

// snapshot returns the caches of the table.
func (t *neighborTable) snapshot() []*neighborCache {
	t.regMu.Lock()
	defer t.regMu.Unlock()
	return append([]*neighborCache(nil), t.caches...)
}

// entries returns the count of dynamic entries of the table, which is
// tbl->gc_entries in Linux.
func (t *neighborTable) entries() int32 {
	var total int32
	for _, c := range t.snapshot() {
		total += c.mu.dynamic.count.Load()
	}
	return total
}

// admitLocked decides whether the table accepts one more dynamic entry. It
// follows neigh_alloc: a table with gc_thresh3 entries, or with gc_thresh2
// entries and no forced collection for five seconds, runs a forced collection.
// The table refuses the entry only when the collection frees nothing and the
// table holds gc_thresh3 entries or more. Linux then logs "neighbor table
// overflow!" and fails with ENOBUFS.
//
// The caller holds allocMu.
func (t *neighborTable) admitLocked(clock tcpip.Clock) bool {
	th := t.thresholdsLocked()
	entries := t.entries()
	now := clock.NowMonotonic()
	if entries < th.Thresh3 && (entries < th.Thresh2 || now.Sub(t.lastFlush) <= neighborGCRecent) {
		return true
	}
	// The collection counts the entry that the caller adds.
	return t.forcedGCLocked(clock, int64(entries)+1-int64(th.Thresh2)) > 0 || entries < th.Thresh3
}

// forcedGCLocked removes the entries that neigh_forced_gc removes: failed
// entries, entries for a multicast address, and entries that did not change
// for five seconds. An entry with a running timer (incomplete, reachable,
// delay, and probe) holds a reference in Linux, so it stays. It stops after
// maxClean removals, or after neighborGCBudget. It returns the count of
// removed entries.
func (t *neighborTable) forcedGCLocked(clock tcpip.Clock, maxClean int64) int {
	now := clock.NowMonotonic()
	deadline := now.Add(neighborGCBudget)
	tref := now.Add(-neighborGCRecent)
	shrunk, loop := 0, 0
	for _, c := range t.snapshot() {
		c.mu.Lock()
		for e := c.mu.dynamic.lru.Back(); e != nil; {
			prev := e.Prev()
			e.mu.Lock()
			switch e.mu.neigh.State {
			case Stale, Unreachable:
				if e.mu.neigh.State == Unreachable ||
					isMulticastNeighbor(e.mu.neigh.Addr) ||
					e.mu.neigh.UpdatedAt.Before(tref) || e.mu.neigh.UpdatedAt.After(now) {
					c.mu.dynamic.lru.Remove(e)
					delete(c.mu.cache, e.mu.neigh.Addr)
					c.mu.dynamic.count.Add(-1)
					e.removeLocked()
					shrunk++
				}
				e.mu.Unlock()
				if int64(shrunk) >= maxClean {
					c.mu.Unlock()
					t.lastFlush = clock.NowMonotonic()
					return shrunk
				}
				loop++
				if loop == neighborGCBudgetStep {
					if clock.NowMonotonic().After(deadline) {
						c.mu.Unlock()
						return shrunk
					}
					loop = 0
				}
			default:
				e.mu.Unlock()
			}
			e = prev
		}
		c.mu.Unlock()
	}
	t.lastFlush = clock.NowMonotonic()
	return shrunk
}

// isMulticastNeighbor reports whether addr is a multicast IP address.
func isMulticastNeighbor(addr tcpip.Address) bool {
	if addr.Len() == header.IPv4AddressSize {
		return header.IsV4MulticastAddress(addr)
	}
	return header.IsV6MulticastAddress(addr)
}
