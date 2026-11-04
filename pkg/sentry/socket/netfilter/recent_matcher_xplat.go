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
	"container/list"
	"fmt"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	bitsutil "z.gfire.dev/gvx/pkg/bits"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the iptables "recent" match (net/netfilter/xt_recent.c).
// kube-proxy uses it for the session affinity of a Service. A rule with --set
// records the address of a packet in a named list, and a rule with --rcheck or
// --update matches when the address was seen recently.

const (
	matcherNameRecent = "recent"

	recentRevision0 uint8 = 0
	recentRevision1 uint8 = 1

	// recentNameLen is XT_RECENT_NAME_LEN.
	recentNameLen = 200

	// The offsets and sizes of struct xt_recent_mtinfo and xt_recent_mtinfo_v1.
	recentOffSeconds  = 0
	recentOffHitCount = 4
	recentOffCheckSet = 8
	recentOffInvert   = 9
	recentOffName     = 10
	recentOffSide     = recentOffName + recentNameLen
	recentOffMask     = 212
	recentInfoSizeV0  = 212
	recentInfoSizeV1  = recentOffMask + 16

	// The bits of check_set.
	recentCheck  uint8 = 1 << 0
	recentSet    uint8 = 1 << 1
	recentUpdate uint8 = 1 << 2
	recentRemove uint8 = 1 << 3
	recentTTL    uint8 = 1 << 4
	recentReap   uint8 = 1 << 5

	recentValidFlags = recentCheck | recentSet | recentUpdate | recentRemove | recentTTL | recentReap
	recentModifiers  = recentTTL | recentReap

	// recentSideDest is XT_RECENT_DEST. Any other value selects the source.
	recentSideDest uint8 = 1

	// recentListTotal is the default of the module parameter ip_list_tot:
	// the count of addresses in one list.
	recentListTotal = 100

	// recentMaxStamps is XT_RECENT_MAX_NSTAMPS. A hit count must be smaller.
	recentMaxStamps = 65536

	// recentDefaultStamps is the count of time stamps of each address when
	// no rule of the list has a hit count.
	recentDefaultStamps = 32
)

func init() {
	registerMatchMaker(recentMarshaler{rev: recentRevision0})
	registerMatchMaker(recentMarshaler{rev: recentRevision1})
}

type recentMarshaler struct {
	rev uint8
}

func (rm recentMarshaler) name() string { return matcherNameRecent }

func (rm recentMarshaler) revision() uint8 { return rm.rev }

func recentInfoSize(rev uint8) int {
	if rev == recentRevision0 {
		return recentInfoSizeV0
	}
	return recentInfoSizeV1
}

func (rm recentMarshaler) marshal(mr matcher) []byte {
	m := mr.(*RecentMatcher)
	buf := marshalEntryMatch(matcherNameRecent, m.raw)
	buf[revisionOffset] = m.rev
	return buf
}

func (rm recentMarshaler) unmarshal(_ IDMapper, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	size := recentInfoSize(rm.rev)
	if want := bitsutil.AlignUp(size, 8); len(buf) != want {
		return nil, fmt.Errorf("recent: buf has size %d, want %d", len(buf), want)
	}
	m := &RecentMatcher{
		rev:      rm.rev,
		raw:      append([]byte(nil), buf[:size]...),
		seconds:  hostarch.ByteOrder.Uint32(buf[recentOffSeconds:]),
		hitCount: hostarch.ByteOrder.Uint32(buf[recentOffHitCount:]),
		checkSet: buf[recentOffCheckSet],
		invert:   buf[recentOffInvert] != 0,
		side:     buf[recentOffSide],
	}
	// Revision 0 has no mask. Linux gives it the mask of all ones.
	for i := range m.mask {
		m.mask[i] = 0xff
	}
	if rm.rev == recentRevision1 {
		copy(m.mask[:], buf[recentOffMask:recentOffMask+16])
	}
	name := buf[recentOffName : recentOffName+recentNameLen]
	end := bytes.IndexByte(name, 0)
	if end <= 0 {
		return nil, fmt.Errorf("recent: the list name is empty or not terminated")
	}
	m.listName = string(name[:end])
	if err := m.check(); err != nil {
		return nil, err
	}
	nflog("parsed recent: list %q check_set 0x%x seconds %d hitcount %d", m.listName, m.checkSet, m.seconds, m.hitCount)
	return m, nil
}

// check applies the rules of recent_mt_check.
func (m *RecentMatcher) check() error {
	if m.checkSet&^recentValidFlags != 0 {
		return fmt.Errorf("recent: invalid flags 0x%x", m.checkSet)
	}
	if bits.OnesCount8(m.checkSet&(recentSet|recentRemove|recentCheck|recentUpdate)) != 1 {
		return fmt.Errorf("recent: need exactly one of --set, --remove, --rcheck and --update")
	}
	if m.checkSet&(recentSet|recentRemove) != 0 && (m.seconds != 0 || m.hitCount != 0 || m.checkSet&recentModifiers != 0) {
		return fmt.Errorf("recent: --set and --remove take no --seconds, --hitcount, --rttl or --reap")
	}
	if m.checkSet&recentReap != 0 && m.seconds == 0 {
		return fmt.Errorf("recent: --reap needs --seconds")
	}
	if m.hitCount >= recentMaxStamps {
		return fmt.Errorf("recent: hitcount %d is larger than the maximum %d", m.hitCount, recentMaxStamps-1)
	}
	if m.listName == "." || m.listName == ".." || bytes.IndexByte([]byte(m.listName), '/') >= 0 {
		return fmt.Errorf("recent: invalid list name %q", m.listName)
	}
	return nil
}

// stampCount returns the count of time stamps that the rule needs for each
// address, a power of two as in recent_mt_check.
func (m *RecentMatcher) stampCount() int {
	if m.hitCount == 0 {
		return recentDefaultStamps
	}
	n := 1
	for n < int(m.hitCount) {
		n <<= 1
	}
	return n
}

// RecentMatcher matches packets by the history of their address in a named
// list. The lists belong to the network stack of the rule.
type RecentMatcher struct {
	rev uint8
	// raw is the user struct as parsed. Marshal returns it unchanged, as
	// Linux does.
	raw      []byte
	seconds  uint32
	hitCount uint32
	checkSet uint8
	invert   bool
	side     uint8
	mask     [16]byte
	listName string

	// table is the named list. bindStack sets it before the rule is
	// published, so Match reads it without a lock.
	table *recentTable
	// released is set when the rule gives up its reference to table.
	released atomic.Bool
}

func (*RecentMatcher) name() string { return matcherNameRecent }

func (m *RecentMatcher) revision() uint8 { return m.rev }

// bindStack implements stackBinder.bindStack. Rules of one stack that name the
// same list share it.
func (m *RecentMatcher) bindStack(stk *stack.Stack) {
	t := recentTables.registry(stk).acquire(m.listName, m.mask, m.stampCount())
	m.table = t
	// The cleanup releases the list if the rule is lost without a
	// replacement of its table, for example with its network stack.
	runtime.AddCleanup(m, func(r *recentRelease) { r.run() }, &recentRelease{table: t, released: &m.released})
}

// releaseStack implements stackReleaser.releaseStack.
func (m *RecentMatcher) releaseStack() {
	(&recentRelease{table: m.table, released: &m.released}).run()
}

// recentRelease drops the reference of one rule to its list once.
type recentRelease struct {
	table    *recentTable
	released *atomic.Bool
}

func (r *recentRelease) run() {
	if r.table != nil && r.released.CompareAndSwap(false, true) {
		r.table.owner.release(r.table)
	}
}

// Match implements stack.Matcher.Match.
func (m *RecentMatcher) Match(hook stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	src, dst, ok := packetAddresses(pkt)
	if !ok || m.table == nil {
		return false, true
	}
	addr := src
	if m.side == recentSideDest {
		addr = dst
	}
	ttl := packetTTL(pkt)
	// Linux compares the TTL as it was before forwarding. Here FORWARD runs
	// before the TTL decrement, and POSTROUTING runs after it.
	if hook == stack.Postrouting && pkt.Owner == nil {
		ttl++
	}
	return m.table.match(m, pkt.NetworkProtocolNumber, addr.AsSlice(), ttl), false
}

// packetTTL returns the TTL or hop limit of the packet.
func packetTTL(pkt *stack.PacketBuffer) uint8 {
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		if hdr := header.IPv4(pkt.NetworkHeader().Slice()); len(hdr) >= header.IPv4MinimumSize {
			return hdr.TTL()
		}
	case header.IPv6ProtocolNumber:
		if hdr := header.IPv6(pkt.NetworkHeader().Slice()); len(hdr) >= header.IPv6MinimumSize {
			return hdr.HopLimit()
		}
	}
	return 0
}

type recentKey struct {
	proto tcpip.NetworkProtocolNumber
	addr  [16]byte
}

type recentEntry struct {
	key    recentKey
	ttl    uint8
	stamps []time.Duration
	// nstamps is the count of valid stamps, and index the slot of the next
	// stamp.
	nstamps int
	index   int
	lru     *list.Element
}

// last returns the newest stamp.
func (e *recentEntry) last() time.Duration {
	return e.stamps[(e.index+len(e.stamps)-1)%len(e.stamps)]
}

// recentTable is one named list. The LRU list holds the entries from the
// oldest update to the newest.
type recentTable struct {
	owner *recentRegistry
	name  string
	clock func() time.Duration
	// mask comes from the first rule that names the list, as in Linux.
	mask [16]byte

	mu sync.Mutex
	// refs is the count of rules that name the list. The registry lock
	// guards it.
	refs int
	// stamps is the count of time stamps of each entry.
	stamps  int
	entries map[recentKey]*recentEntry
	lru     list.List
}

// match runs recent_mt for one packet.
func (t *recentTable) match(m *RecentMatcher, proto tcpip.NetworkProtocolNumber, addr []byte, ttl uint8) bool {
	key := recentKey{proto: proto}
	for i := range addr {
		key.addr[i] = addr[i] & t.mask[i]
	}
	now := t.clock()
	ret := m.invert

	t.mu.Lock()
	defer t.mu.Unlock()

	e := t.entries[key]
	// A TTL of 0 on either side matches any TTL, as in recent_entry_lookup.
	if e != nil && m.checkSet&recentTTL != 0 && ttl != 0 && e.ttl != 0 && e.ttl != ttl {
		e = nil
	}
	if e == nil {
		if m.checkSet&recentSet == 0 {
			return ret
		}
		t.insert(key, ttl, now)
		return !ret
	}

	switch {
	case m.checkSet&recentSet != 0:
		ret = !ret
	case m.checkSet&recentRemove != 0:
		t.remove(e)
		return !ret
	case m.checkSet&(recentCheck|recentUpdate) != 0:
		limit := now - time.Duration(m.seconds)*time.Second
		hits := uint32(0)
		for i := 0; i < e.nstamps; i++ {
			if m.seconds != 0 && e.stamps[i] < limit {
				continue
			}
			hits++
			if m.hitCount == 0 || hits >= m.hitCount {
				ret = !ret
				break
			}
		}
		if m.checkSet&recentReap != 0 {
			t.reap(limit, e, m.checkSet&recentUpdate != 0 && ret)
			if _, ok := t.entries[key]; !ok {
				return ret
			}
		}
	}

	if m.checkSet&recentSet != 0 || (m.checkSet&recentUpdate != 0 && ret) {
		t.update(e, now)
		e.ttl = ttl
	}
	return ret
}

// insert adds a new entry with one stamp. A full list drops its oldest entry.
func (t *recentTable) insert(key recentKey, ttl uint8, now time.Duration) {
	if len(t.entries) >= recentListTotal {
		t.remove(t.lru.Front().Value.(*recentEntry))
	}
	e := &recentEntry{key: key, ttl: ttl, stamps: make([]time.Duration, t.stamps), nstamps: 1, index: 1}
	e.stamps[0] = now
	e.lru = t.lru.PushBack(e)
	t.entries[key] = e
}

// update adds a stamp and makes the entry the newest.
func (t *recentTable) update(e *recentEntry, now time.Duration) {
	if e.index >= len(e.stamps) {
		e.index = 0
	}
	e.stamps[e.index] = now
	e.index++
	if e.index > e.nstamps {
		e.nstamps = e.index
	}
	t.lru.MoveToBack(e.lru)
}

func (t *recentTable) remove(e *recentEntry) {
	t.lru.Remove(e.lru)
	delete(t.entries, e.key)
}

// reap removes the oldest entry when its newest stamp is older than limit,
// unless that entry is the one about to be updated.
func (t *recentTable) reap(limit time.Duration, working *recentEntry, update bool) {
	front := t.lru.Front()
	if front == nil {
		return
	}
	e := front.Value.(*recentEntry)
	if e == working && update {
		return
	}
	if e.last() < limit {
		t.remove(e)
	}
}

// recentRegistry holds the named lists of one network stack.
type recentRegistry struct {
	mu     sync.Mutex
	tables map[string]*recentTable
	clock  func() time.Duration
}

// acquire returns the list name and counts one more rule that uses it. A new
// list takes mask. A rule that needs more stamps than the list has grows the
// list and empties it, as recent_mt_check does.
func (r *recentRegistry) acquire(name string, mask [16]byte, stamps int) *recentTable {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.tables[name]
	if t == nil {
		t = &recentTable{owner: r, name: name, clock: r.clock, mask: mask, stamps: stamps, entries: make(map[recentKey]*recentEntry)}
		r.tables[name] = t
	}
	t.refs++
	if stamps > t.stamps {
		t.mu.Lock()
		t.stamps = stamps
		clear(t.entries)
		t.lru.Init()
		t.mu.Unlock()
	}
	return t
}

// release drops one rule of the list, and drops the list with its last rule,
// as recent_mt_destroy does.
func (r *recentRegistry) release(t *recentTable) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t.refs--
	if t.refs == 0 && r.tables[t.name] == t {
		delete(r.tables, t.name)
	}
}

// recentStacks maps each network stack to its lists.
type recentStacks struct {
	mu     sync.Mutex
	stacks map[weak.Pointer[stack.Stack]]*recentRegistry
}

var recentTables = recentStacks{stacks: make(map[weak.Pointer[stack.Stack]]*recentRegistry)}

// registry returns the lists of stk.
func (s *recentStacks) registry(stk *stack.Stack) *recentRegistry {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := weak.Make(stk)
	if r := s.stacks[key]; r != nil {
		return r
	}
	clock := stk.Clock()
	epoch := clock.NowMonotonic()
	r := &recentRegistry{
		tables: make(map[string]*recentTable),
		clock:  func() time.Duration { return clock.NowMonotonic().Sub(epoch) },
	}
	s.stacks[key] = r
	runtime.AddCleanup(stk, func(key weak.Pointer[stack.Stack]) {
		s.mu.Lock()
		delete(s.stacks, key)
		s.mu.Unlock()
	}, key)
	return r
}
