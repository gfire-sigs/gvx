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

package ipset

import (
	"math/bits"
	"slices"
	"time"
)

// IP protocol numbers that set types read.
const (
	protoICMP    = 1
	protoTCP     = 6
	protoUDP     = 17
	protoICMPv6  = 58
	protoSCTP    = 132
	protoUDPLite = 136
)

// protoWithPorts reports whether the protocol has ports
// (ip_set_proto_with_ports).
func protoWithPorts(proto uint8) bool {
	switch proto {
	case protoTCP, protoUDP, protoUDPLite, protoSCTP:
		return true
	}
	return false
}

// hashKey is the identity of an element of a hash set or a bitmap set. A
// component that a type does not use stays zero. cidr and cidr2 are the prefix
// lengths of the components that are networks.
//
// +stateify savable
type hashKey struct {
	ip, ip2     Addr
	port        uint16
	proto       uint8
	cidr, cidr2 uint8
}

// entry is a stored element.
//
// +stateify savable
type entry struct {
	key     hashKey
	live    bool
	nomatch bool
	extensionData
}

// prefixSet counts the elements of a set for each prefix length of a network
// component. list holds the prefix lengths in use from the longest to the
// shortest, as the arrays of nets of Linux do.
//
// +stateify savable
type prefixSet struct {
	counts [129]uint32
	list   []uint8
}

func (p *prefixSet) add(cidr uint8) {
	if p.counts[cidr]++; p.counts[cidr] > 1 {
		return
	}
	i, _ := slices.BinarySearchFunc(p.list, cidr, func(have, want uint8) int { return int(want) - int(have) })
	p.list = slices.Insert(p.list, i, cidr)
}

func (p *prefixSet) del(cidr uint8) {
	if p.counts[cidr] == 0 {
		return
	}
	if p.counts[cidr]--; p.counts[cidr] > 0 {
		return
	}
	if i := slices.Index(p.list, cidr); i >= 0 {
		p.list = slices.Delete(p.list, i, i+1)
	}
}

// store keeps the elements of a hash set or a bitmap set in the order of their
// insertion. A removed element leaves a dead slot, so that a listing in
// progress keeps its position. The slots are compacted when no listing runs.
//
// +stateify savable
type store struct {
	index   map[hashKey]int
	entries []entry
	live    int
	// listings counts the cursors that read the entries.
	listings int `state:"nosave"`
	prefix   [2]prefixSet
	// purgeAt is the entry count at which the next add looks for expired
	// elements.
	purgeAt int
}

func (st *store) init() {
	st.index = make(map[hashKey]int)
	st.purgeAt = 1024
}

func (st *store) find(k hashKey) *entry {
	if i, ok := st.index[k]; ok {
		return &st.entries[i]
	}
	return nil
}

// liveCount counts the elements that have not timed out.
func (st *store) liveCount(s *Set, now time.Duration) int {
	if !s.withTimeout {
		return st.live
	}
	n := 0
	for i := range st.entries {
		if e := &st.entries[i]; e.live && !s.expired(&e.extensionData, now) {
			n++
		}
	}
	return n
}

// insert appends an element and returns it.
func (st *store) insert(s *Set, e entry) *entry {
	e.live = true
	st.index[e.key] = len(st.entries)
	st.entries = append(st.entries, e)
	st.live++
	st.track(s, &e.key, true)
	return &st.entries[len(st.entries)-1]
}

// remove deletes the element at slot i and compacts the slots. A caller that
// holds slot numbers uses removeSlot instead.
func (st *store) remove(s *Set, i int) {
	st.removeSlot(s, i)
	st.compact()
}

// removeSlot deletes the element at slot i and keeps every other slot number.
func (st *store) removeSlot(s *Set, i int) {
	e := &st.entries[i]
	delete(st.index, e.key)
	st.track(s, &e.key, false)
	*e = entry{}
	st.live--
}

// track updates the prefix counts for a network component.
func (st *store) track(s *Set, k *hashKey, add bool) {
	if s.spec.ipNet {
		if add {
			st.prefix[0].add(k.cidr)
		} else {
			st.prefix[0].del(k.cidr)
		}
	}
	if s.spec.ip2Net {
		if add {
			st.prefix[1].add(k.cidr2)
		} else {
			st.prefix[1].del(k.cidr2)
		}
	}
}

// compact removes the dead slots when they take most of the entries.
func (st *store) compact() {
	if st.listings > 0 || len(st.entries) < 64 || st.live*2 > len(st.entries) {
		return
	}
	kept := st.entries[:0]
	for _, e := range st.entries {
		if e.live {
			kept = append(kept, e)
		}
	}
	clear(st.entries[len(kept):])
	st.entries = kept
	clear(st.index)
	for i := range kept {
		st.index[kept[i].key] = i
	}
}

// flush removes every element.
func (st *store) flush() {
	clear(st.index)
	clear(st.entries)
	if st.listings == 0 {
		st.entries = st.entries[:0]
	}
	st.live = 0
	st.prefix = [2]prefixSet{}
}

// purgeExpired removes the elements that have timed out.
func (st *store) purgeExpired(s *Set, now time.Duration) {
	if !s.withTimeout {
		return
	}
	for i := range st.entries {
		if e := &st.entries[i]; e.live && s.expired(&e.extensionData, now) {
			st.removeSlot(s, i)
		}
	}
	// Compaction moves the slots, so it runs once after the loop.
	st.compact()
	st.purgeAt = max(1024, 2*st.live)
}

// createHash fills the hash part of a set from a create request. It is the
// create function of a Linux hash type.
func (s *Set) createHash(p *CreateParams) int {
	if p.Family != FamilyIPv4 && p.Family != FamilyIPv6 {
		return -ErrInvalidFamily
	}
	host := hostBits(s.family)
	s.netmask = host
	s.bitmask = prefixMask(int(host), addrSize(s.family))
	if s.spec.netmask && p.given(GivenNetmask) {
		if p.Netmask == 0 || p.Netmask > host {
			return -ErrInvalidNetmask
		}
		s.netmask = p.Netmask
		s.bitmask = prefixMask(int(p.Netmask), addrSize(s.family))
	}
	if s.spec.bitmask && p.given(GivenBitmask) {
		if p.given(GivenNetmask) {
			return -ErrBitmaskNetmaskExcl
		}
		mask := p.Bitmask
		if mask == (Addr{}) {
			return -ErrInvalidNetmask
		}
		// The bytes past the address stay zero for IPv4.
		s.bitmask = mask
	}
	s.hashSize = defaultHashSize
	if p.given(GivenHashSize) {
		s.hashSize = max(p.HashSize, minimalHashSize)
	}
	// Round up to the first power of two, as the table of Linux does.
	s.hashSize = 1 << bits.Len32(s.hashSize-1)
	s.maxElem = defaultMaxElem
	if p.given(GivenMaxElem) {
		s.maxElem = p.MaxElem
	}
	s.initVal = randomInitVal()
	if p.given(GivenInitVal) {
		s.initVal = p.InitVal
	}
	s.bucketSize = ahashMaxSize
	if p.given(GivenBucketSize) {
		s.bucketSize = min(max(p.BucketSize, ahashInitSize), ahashMaxSize)
		if s.bucketSize%2 != 0 {
			s.bucketSize++
		}
	}
	return 0
}

// isHost reports whether the prefix length of a network component is a host
// prefix.
func (s *Set) isHost(cidr uint8) bool { return cidr == hostBits(s.family) }

// hashAdd stores an element. It returns zero or a negative error code.
//
// Preconditions: s.mu is held.
func (s *Set) hashAdd(k hashKey, nomatch bool, x *ext, flags uint32, now time.Duration) int {
	st := &s.store
	if i, ok := st.index[k]; ok {
		e := &st.entries[i]
		expired := s.expired(&e.extensionData, now)
		if !expired && flags&FlagExist == 0 {
			return -ErrExist
		}
		if expired {
			e.extensionData = extensionData{}
		}
		e.nomatch = nomatch
		s.initExtensions(&e.extensionData, x, now)
		return 0
	}
	if len(st.entries) >= st.purgeAt || st.live >= int(s.maxElem) {
		st.purgeExpired(s, now)
	}
	if st.live >= int(s.maxElem) {
		if !s.forceadd || st.live == 0 {
			return -ErrHashFull
		}
		// Replace the oldest element, as forceadd of Linux replaces one.
		for i := range st.entries {
			if st.entries[i].live {
				st.remove(s, i)
				break
			}
		}
	}
	e := entry{key: k, nomatch: nomatch}
	s.initExtensions(&e.extensionData, x, now)
	st.insert(s, e)
	return 0
}

// hashDel removes an element.
//
// Preconditions: s.mu is held.
func (s *Set) hashDel(k hashKey, now time.Duration) int {
	i, ok := s.store.index[k]
	if !ok {
		return -ErrExist
	}
	expired := s.expired(&s.store.entries[i].extensionData, now)
	s.store.remove(s, i)
	if expired {
		return -ErrExist
	}
	return 0
}

// hashDataMatch is mtype_data_match: it applies the extensions of an element
// and then reports whether the element matches, or is a nomatch element.
func (s *Set) hashDataMatch(e *entry, x *ext, o *KOpt, flags uint32, now time.Duration) int {
	if !s.matchExtensions(&e.extensionData, x, o, flags, now) {
		return 0
	}
	if e.nomatch {
		return -errnoENOTEMPTY
	}
	return 1
}

// hashTest looks an element up. It returns 1 for a match, zero for none, and
// -ENOTEMPTY when a nomatch element matches.
//
// Preconditions: s.mu is held.
func (s *Set) hashTest(k hashKey, x *ext, o *KOpt, flags uint32, now time.Duration) int {
	if s.spec.ipNet || s.spec.ip2Net {
		hostQuery := (!s.spec.ipNet || s.isHost(k.cidr)) && (!s.spec.ip2Net || s.isHost(k.cidr2))
		if hostQuery {
			return s.hashTestCIDRs(k, x, o, flags, now)
		}
	}
	if i, ok := s.store.index[k]; ok {
		if ret := s.hashDataMatch(&s.store.entries[i], x, o, flags, now); ret != 0 {
			return ret
		}
	}
	return 0
}

// hashTestCIDRs tests a host against every prefix length that the set holds,
// the longest first (mtype_test_cidrs).
func (s *Set) hashTestCIDRs(k hashKey, x *ext, o *KOpt, flags uint32, now time.Duration) int {
	size := addrSize(s.family)
	first := []uint8{0}
	if s.spec.ipNet {
		first = s.store.prefix[0].list
	}
	second := []uint8{0}
	if s.spec.ip2Net {
		second = s.store.prefix[1].list
	}
	for _, c0 := range first {
		for _, c1 := range second {
			d := k
			if s.spec.ipNet {
				d.ip, d.cidr = k.ip.and(prefixMask(int(c0), size)), c0
			}
			if s.spec.ip2Net {
				d.ip2, d.cidr2 = k.ip2.and(prefixMask(int(c1), size)), c1
			}
			i, ok := s.store.index[d]
			if !ok {
				continue
			}
			if ret := s.hashDataMatch(&s.store.entries[i], x, o, flags, now); ret != 0 {
				return ret
			}
		}
	}
	return 0
}

// hashApply runs one operation on one element key.
func (s *Set) hashApply(adt Adt, k hashKey, nomatch bool, x *ext, flags uint32, now time.Duration) int {
	switch adt {
	case AdtAdd:
		return s.hashAdd(k, nomatch, x, flags, now)
	case AdtDel:
		return s.hashDel(k, now)
	}
	return s.hashTest(k, x, nil, flags, now)
}

// component is one address of an element together with its prefix length.
type component struct {
	addr Addr
	cidr uint8
}

// dimension is the set of addresses that one address attribute of a request
// names: one address, a range of hosts, or the blocks of a range of networks.
type dimension struct {
	one    component
	from   uint32
	to     uint32
	ranged bool
	blocks bool
	// step is the distance between two hosts of a range. It is 1, except for a
	// set with the create option netmask, which has one element for each
	// network of the netmask.
	step uint32
	done bool
}

// next returns the next component of the dimension and reports whether one
// existed. A copy of a newly built dimension starts at the beginning.
func (d *dimension) next() (component, bool) {
	if d.done {
		return component{}, false
	}
	if !d.ranged {
		d.done = true
		return d.one, true
	}
	if d.blocks {
		last, c := rangeToCIDR(d.from, d.to)
		out := component{addr4(d.from), c}
		if last >= d.to || last == ^uint32(0) {
			d.done = true
		} else {
			d.from = last + 1
		}
		return out, true
	}
	step := max(d.step, 1)
	out := component{addr4(d.from), 0}
	if d.to-d.from < step {
		d.done = true
	} else {
		d.from += step
	}
	return out, true
}

// newDimension validates an address attribute with its range or prefix.
// isNet tells that the address is a network. It returns a negative error code
// for an invalid request.
func (s *Set) newDimension(adt Adt, ip, ipTo Addr, hasTo bool, cidr uint8, hasCIDR bool, isNet bool) (dimension, int) {
	host := hostBits(s.family)
	size := addrSize(s.family)
	if hasCIDR && (cidr == 0 || cidr > host) {
		return dimension{}, -ErrInvalidCIDR
	}
	if isNet {
		if !hasCIDR {
			cidr = host
		}
		if adt == AdtTest || !hasTo {
			return dimension{one: component{ip.and(prefixMask(int(cidr), size)), cidr}}, 0
		}
		if s.family == FamilyIPv6 {
			return dimension{}, -ErrHashRangeUnsupported
		}
		from, to := ip.ip4(), ipTo.ip4()
		if to < from {
			from, to = to, from
		}
		if from == 0 && to == ^uint32(0) {
			return dimension{}, -ErrHashRange
		}
		return dimension{from: from, to: to, ranged: true, blocks: true}, 0
	}
	if adt == AdtTest || (!hasTo && !hasCIDR) {
		return dimension{one: component{addr: ip}}, 0
	}
	if s.family == FamilyIPv6 {
		if hasTo || cidr != host {
			return dimension{}, -ErrHashRangeUnsupported
		}
		return dimension{one: component{addr: ip}}, 0
	}
	from := ip.ip4()
	to := from
	if hasTo {
		to = ipTo.ip4()
		if from > to {
			from, to = to, from
		}
	} else {
		mask := ^uint32(0) << (32 - uint(cidr))
		from &= mask
		to = from | ^mask
	}
	step := uint32(1)
	if s.spec.netmask && s.netmask < 32 {
		// A set with netmask N has one element for each network of N bits, so a
		// range starts at a network and steps from network to network, as
		// hash_ip4_uadt does.
		from &= ^uint32(0) << (32 - uint(s.netmask))
		step = 1 << (32 - uint(s.netmask))
	}
	return dimension{from: from, to: to, ranged: true, step: step}, 0
}

// rangeChunk is the count of elements that a range operation changes in one
// hold of the lock of the set. It is IPSET_MAX_RANGE of Linux. A longer range
// goes on in the next hold, so a packet that tests the set waits for one chunk
// at most.
const rangeChunk = 1 << 14

// hashUadt is the uadt function of the hash types: it runs the operation on
// the element that a request names.
func (s *Set) hashUadt(adt Adt, e *Element, flags uint32) int {
	x, ret := s.getExtensions(e)
	if ret != 0 {
		return ret
	}
	spec := s.spec
	if !e.has(HasIP) || (spec.hasIP2 && !e.has(HasIP2)) {
		return -ErrProtocol
	}
	var port, portTo uint16
	var proto uint8
	if spec.hasPort {
		if !e.has(HasPort) {
			return -ErrProtocol
		}
		port = e.Port
		if !e.has(HasProto) {
			return -ErrMissingProto
		}
		proto = e.Proto
		if proto == 0 {
			return -ErrInvalidProto
		}
		withPorts := protoWithPorts(proto)
		icmp := proto == protoICMP
		if s.family == FamilyIPv6 {
			icmp = proto == protoICMPv6
		}
		if !withPorts && !icmp {
			port = 0
		}
		portTo = port
		if withPorts && e.has(HasPortTo) && adt != AdtTest {
			portTo = e.PortTo
			if port > portTo {
				port, portTo = portTo, port
			}
		}
	}
	nomatch := e.has(HasCadtFlags) && spec.features&featureNomatch != 0 && e.CadtFlags&CadtNomatch != 0

	ip := e.IP
	if !spec.ipNet && (spec.netmask || spec.bitmask) {
		ip = ip.and(s.bitmask)
		if !e.has(HasIPTo) && !e.has(HasCIDR) && ip == (Addr{}) {
			if spec.hasPort {
				return -errnoEINVAL
			}
			return -ErrHashElem
		}
	}
	first, ret := s.newDimension(adt, ip, e.IPTo, e.has(HasIPTo), e.CIDR, e.has(HasCIDR), spec.ipNet)
	if ret != 0 {
		return ret
	}
	second := dimension{}
	if spec.hasIP2 {
		second, ret = s.newDimension(adt, e.IP2, e.IP2To, e.has(HasIP2To), e.CIDR2, e.has(HasCIDR2), spec.ip2Net)
		if ret != 0 {
			return ret
		}
	}
	bitmask := spec.bitmask && spec.ipNet

	makeKey := func(a, b component, p uint16) hashKey {
		k := hashKey{ip: a.addr, ip2: b.addr, port: p, proto: proto}
		if bitmask {
			k.ip, k.ip2 = k.ip.and(s.bitmask), k.ip2.and(s.bitmask)
		}
		if spec.ipNet {
			k.cidr = a.cidr
		}
		if spec.ip2Net {
			k.cidr2 = b.cidr
		}
		return k
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if adt == AdtTest {
		return s.testResult(s.hashApply(adt, makeKey(first.one, second.one, port), nomatch, &x, flags, now), nomatch)
	}
	changed := 0
	for a, ok := first.next(); ok; a, ok = first.next() {
		for p := uint32(port); p <= uint32(portTo); p++ {
			bDim := second
			for b, ok := bDim.next(); ok; b, ok = bDim.next() {
				if changed++; changed%rangeChunk == 0 {
					s.mu.Unlock()
					now = s.now()
					s.mu.Lock()
				}
				if r := s.hashApply(adt, makeKey(a, b, uint16(p)), nomatch, &x, flags, now); r != 0 && !(r == -ErrExist && flags&FlagExist != 0) {
					return r
				}
			}
		}
	}
	return 0
}

// testResult converts the result of a lookup for a TEST command to the code
// that uadt returns: positive for an element that is in the set. With the
// nomatch flag in the request, the test succeeds for a nomatch element only.
func (s *Set) testResult(ret int, requestNomatch bool) int {
	if s.spec.features&featureNomatch != 0 && requestNomatch && (ret > 0 || ret == -errnoENOTEMPTY) {
		return -ret
	}
	return ret
}

// hashKadt is the kadt function of the hash types: it runs the operation on
// the element that a packet makes.
func (s *Set) hashKadt(adt Adt, pkt *Packet, o *KOpt) int {
	spec := s.spec
	pick := func(flag uint32, src, dst Addr) Addr {
		if o.Flags&flag != 0 {
			return src
		}
		return dst
	}
	size := addrSize(s.family)
	var k hashKey
	if spec.hasIP2 {
		flag := KDimThreeSrc
		if spec.dimension == 2 {
			flag = KDimTwoSrc
		}
		k.ip2 = pick(flag, pkt.Src, pkt.Dst)
	}
	k.ip = pick(KDimOneSrc, pkt.Src, pkt.Dst)
	if spec.hasPort {
		if !pkt.PortsOK {
			return -errnoEINVAL
		}
		k.port = pkt.DstPort
		if o.Flags&KDimTwoSrc != 0 {
			k.port = pkt.SrcPort
		}
		k.proto = pkt.Proto
	}

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !spec.ipNet && (spec.netmask || spec.bitmask) {
		k.ip = k.ip.and(s.bitmask)
	}
	if spec.ipNet || spec.ip2Net {
		host := hostBits(s.family)
		longest := func(dim int) uint8 {
			if l := s.store.prefix[dim].list; len(l) > 0 {
				return l[0]
			}
			return host
		}
		if spec.ipNet {
			k.cidr = longest(0)
			if adt == AdtTest {
				k.cidr = host
			}
			k.ip = k.ip.and(prefixMask(int(k.cidr), size))
		}
		if spec.ip2Net {
			k.cidr2 = longest(1)
			if adt == AdtTest {
				k.cidr2 = host
			}
			k.ip2 = k.ip2.and(prefixMask(int(k.cidr2), size))
		}
		if spec.bitmask && spec.ipNet {
			k.ip = k.ip.and(s.bitmask)
			k.ip2 = k.ip2.and(s.bitmask)
		}
	} else if k.ip == (Addr{}) {
		return -errnoEINVAL
	}
	x := ext{timeout: o.timeoutOr(s.defTimeout), packets: 1, bytes: uint64(pkt.Len), target: true}
	if adt == AdtTest {
		return s.hashTest(k, &x, o, o.CmdFlags, now)
	}
	return s.hashApply(adt, k, false, &x, o.CmdFlags, now)
}

// hashElement builds the listed form of a stored element.
func (s *Set) hashElement(e *entry, now time.Duration) Element {
	spec := s.spec
	k := &e.key
	out := Element{Has: HasIP, IP: k.ip}
	if spec.ipNet {
		out.Has |= HasCIDR
		out.CIDR = k.cidr
	}
	if spec.hasPort {
		out.Has |= HasPort | HasProto
		out.Port, out.Proto = k.port, k.proto
	}
	if spec.hasIP2 {
		out.Has |= HasIP2
		out.IP2 = k.ip2
		if spec.ip2Net {
			out.Has |= HasCIDR2
			out.CIDR2 = k.cidr2
		}
	}
	if e.nomatch {
		out.Has |= HasCadtFlags
		out.CadtFlags = CadtNomatch
	}
	s.outputExtensions(&out, &e.extensionData, now)
	return out
}
