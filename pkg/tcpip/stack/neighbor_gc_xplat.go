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
	"math"
	"time"

	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// This file limits dynamic entries in neighbor tables as neigh_alloc and
// neigh_forced_gc in Linux net/core/neighbour.c do. Linux counts entries of
// one protocol table (arp_tbl or nd_tbl) across all links in the network
// namespace. The sysctls net.ipv4.neigh.default.gc_thresh1 to gc_thresh3 and
// their IPv6 equivalents configure those thresholds. Static entries
// (NUD_PERMANENT) stay off the garbage-collection list and have no limit.

// Defaults of gc_thresh1, gc_thresh2, and gc_thresh3 in arp_tbl and nd_tbl.
const (
	DefaultNeighborGCThresh1 = 128
	DefaultNeighborGCThresh2 = 512
	DefaultNeighborGCThresh3 = 1024
)

const (
	// neighborGCRecent is the age below which a stale entry survives forced
	// collection. Linux uses 5 * HZ.
	neighborGCRecent = 5 * time.Second
	// neighborGCBudget bounds the duration of one forced-collection pass.
	// Linux stops after one millisecond.
	neighborGCBudget = time.Millisecond
	// neighborGCBudgetStep is the number of candidates visited between clock
	// reads during forced collection.
	neighborGCBudgetStep = 16
)

// NeighborGCThresholds holds gc_thresh1, gc_thresh2, and gc_thresh3 for one
// neighbor table. Linux accepts values from 0 to MaxInt32 without ordering
// constraints between thresholds.
//
// +stateify savable
type NeighborGCThresholds struct {
	Thresh1, Thresh2, Thresh3 int32
}

// DefaultNeighborGCThresholds returns the default thresholds for a neighbor table.
func DefaultNeighborGCThresholds() NeighborGCThresholds {
	return NeighborGCThresholds{DefaultNeighborGCThresh1, DefaultNeighborGCThresh2, DefaultNeighborGCThresh3}
}

// neighborCacheSlot tracks one registered link cache inside a neighborTable.
type neighborCacheSlot struct {
	cache *neighborCache
	// wideCount reports whether dynamic entries exceeded MaxUint16, where
	// dynamicCacheEntry.count wraps modulo 65536. cache.mu protects wideCount.
	wideCount bool
}

func (s *neighborCacheSlot) dynamicEntries() int64 {
	c := s.cache
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !s.wideCount {
		return int64(c.mu.dynamic.count)
	}
	return int64(c.mu.dynamic.lru.Len())
}

// neighborTable owns the thresholds and registered link caches for one network
// protocol in a Stack.
//
// +stateify savable
type neighborTable struct {
	// allocMu serializes dynamic entry admission and forced collection.
	// Callers acquire allocMu before any neighborCache lock.
	allocMu sync.Mutex `state:"nosave"`
	// allocMu protects thresholds and lastFlush.
	thresholds *NeighborGCThresholds
	lastFlush  tcpip.MonotonicTime

	// regMu protects caches as a leaf lock.
	regMu  sync.Mutex           `state:"nosave"`
	caches []*neighborCacheSlot `state:"nosave"`
}

// neighborTables holds the per-protocol neighbor tables of a Stack.
//
// +stateify savable
type neighborTables struct {
	ipv4, ipv6 neighborTable
}

// of returns the table for protocol, or nil when protocol uses no neighbor table.
func (t *neighborTables) of(protocol tcpip.NetworkProtocolNumber) *neighborTable {
	switch protocol {
	case header.IPv4ProtocolNumber:
		return &t.ipv4
	case header.IPv6ProtocolNumber:
		return &t.ipv6
	}
	return nil
}

// NeighborGCThresholds returns gc_thresh1, gc_thresh2, and gc_thresh3 for protocol.
func (s *Stack) NeighborGCThresholds(protocol tcpip.NetworkProtocolNumber) (NeighborGCThresholds, tcpip.Error) {
	t := s.neighborTables.of(protocol)
	if t == nil {
		return NeighborGCThresholds{}, &tcpip.ErrNotSupported{}
	}
	t.allocMu.Lock()
	defer t.allocMu.Unlock()
	return t.thresholdsLocked(), nil
}

// SetNeighborGCThresholds updates gc_thresh1, gc_thresh2, and gc_thresh3 for
// protocol. Existing entries remain in the table; the next dynamic allocation
// evaluates the new thresholds.
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

// register adds n to the table when absent and returns its slot.
func (t *neighborTable) register(n *neighborCache) *neighborCacheSlot {
	t.regMu.Lock()
	for _, s := range t.caches {
		if s.cache == n {
			t.regMu.Unlock()
			return s
		}
	}
	t.regMu.Unlock()

	n.mu.RLock()
	wide := n.mu.dynamic.lru.Len() > math.MaxUint16
	n.mu.RUnlock()

	t.regMu.Lock()
	defer t.regMu.Unlock()
	for _, s := range t.caches {
		if s.cache == n {
			return s
		}
	}
	s := &neighborCacheSlot{cache: n, wideCount: wide}
	t.caches = append(t.caches, s)
	return s
}

// unregister removes n from the table so entries on a removed NIC stop counting.
func (t *neighborTable) unregister(n *neighborCache) {
	t.regMu.Lock()
	defer t.regMu.Unlock()
	for i, s := range t.caches {
		if s.cache == n {
			t.caches = append(t.caches[:i], t.caches[i+1:]...)
			return
		}
	}
}

// snapshot returns a copy of the registered cache slots.
func (t *neighborTable) snapshot() []*neighborCacheSlot {
	t.regMu.Lock()
	defer t.regMu.Unlock()
	return append([]*neighborCacheSlot(nil), t.caches...)
}

// entries returns the total count of dynamic entries across registered caches.
func (t *neighborTable) entries() int64 {
	var total int64
	for _, s := range t.snapshot() {
		total += s.dynamicEntries()
	}
	return total
}

// getOrCreateDynamicEntry returns the cached entry for remoteAddr or allocates
// a new dynamic entry when the stack neighbor table admits one. It returns nil
// when the table rejects allocation at gc_thresh3.
func (n *neighborCache) getOrCreateDynamicEntry(remoteAddr tcpip.Address) *neighborEntry {
	n.mu.Lock()
	entry, ok := n.mu.cache[remoteAddr]
	if ok {
		n.bumpLocked(entry)
	}
	n.mu.Unlock()
	if ok {
		return entry
	}

	var slot *neighborCacheSlot
	if table := n.nic.stack.neighborTables.of(n.linkRes.LinkAddressProtocol()); table != nil {
		table.allocMu.Lock()
		defer table.allocMu.Unlock()
		slot = table.register(n)
		if !table.admitLocked(n.nic.stack.clock) {
			return nil
		}
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if entry, ok := n.mu.cache[remoteAddr]; ok {
		n.bumpLocked(entry)
		return entry
	}
	if slot != nil && slot.wideCount && n.mu.dynamic.lru.Empty() {
		slot.wideCount = false
	}
	entry = newNeighborEntry(n, remoteAddr, n.state)
	n.mu.cache[remoteAddr] = entry
	n.mu.dynamic.lru.PushFront(entry)
	if slot != nil && n.mu.dynamic.count == math.MaxUint16 {
		slot.wideCount = true
	}
	n.mu.dynamic.count++
	return entry
}

// bumpLocked moves a dynamic entry to the front of the LRU list.
//
// +checklocks:n.mu.neighborCacheRWMutex
func (n *neighborCache) bumpLocked(entry *neighborEntry) {
	entry.mu.RLock()
	if entry.mu.neigh.State != Static {
		n.mu.dynamic.lru.Remove(entry)
		n.mu.dynamic.lru.PushFront(entry)
	}
	entry.mu.RUnlock()
}

// admitLocked reports whether the table admits one new dynamic entry. At
// gc_thresh3, or at gc_thresh2 after five seconds since the last flush, it runs
// forced collection first. It rejects allocation when collection frees no entry
// at or above gc_thresh3. Caller holds allocMu.
func (t *neighborTable) admitLocked(clock tcpip.Clock) bool {
	th := t.thresholdsLocked()
	entries := t.entries()
	thresh2 := int64(th.Thresh2)
	thresh3 := int64(th.Thresh3)
	now := clock.NowMonotonic()
	if entries < thresh3 && (entries < thresh2 || now.Sub(t.lastFlush) <= neighborGCRecent) {
		return true
	}
	// Count the incoming entry when computing forced-collection target removals.
	return t.forcedGCLocked(clock, entries+1-thresh2) > 0 || entries < thresh3
}

// forcedGCLocked evicts unreachable entries, multicast entries, and stale
// entries older than five seconds, matching Linux neigh_forced_gc. Entries with
// active timers remain in the cache. It stops after maxClean removals or
// neighborGCBudget and returns the number of evicted entries.
func (t *neighborTable) forcedGCLocked(clock tcpip.Clock, maxClean int64) int {
	now := clock.NowMonotonic()
	deadline := now.Add(neighborGCBudget)
	tref := now.Add(-neighborGCRecent)
	shrunk, loop := 0, 0
	for _, s := range t.snapshot() {
		c := s.cache
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
					c.mu.dynamic.count--
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

// registerRestoredNeighborCaches registers link caches that carry restored
// dynamic entries so forced collection counts them after restore.
func (n *nic) registerRestoredNeighborCaches() {
	for protocol, l := range n.linkAddrResolvers {
		l.neigh.mu.RLock()
		hasDynamic := !l.neigh.mu.dynamic.lru.Empty()
		l.neigh.mu.RUnlock()
		if !hasDynamic {
			continue
		}
		if t := n.stack.neighborTables.of(protocol); t != nil {
			t.register(&l.neigh)
		}
	}
}
