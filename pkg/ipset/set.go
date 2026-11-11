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
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

// Adt is an operation on the elements of a set (enum ipset_adt).
type Adt uint8

// The operations on the elements of a set.
const (
	AdtAdd Adt = iota
	AdtDel
	AdtTest
)

// CreateParams holds the attributes of the CREATE command.
type CreateParams struct {
	Name     string
	TypeName string
	Family   uint8
	Revision uint8
	// Exist is true when the request has no NLM_F_EXCL flag. An existing set
	// with the same parameters then is no error.
	Exist bool

	Has Present
	// The attributes of IPSET_ATTR_DATA.
	HashSize   uint32
	MaxElem    uint32
	InitVal    uint32
	BucketSize uint8
	Netmask    uint8
	Bitmask    Addr
	Timeout    uint32
	CadtFlags  uint32
	PortFrom   uint16
	PortTo     uint16
	Size       uint32
	// Given has a bit for each attribute of IPSET_ATTR_DATA that the
	// request carries.
	Given CreateGiven
}

// CreateGiven is a bit set of the create attributes of a request.
type CreateGiven uint16

// The create attributes.
const (
	GivenHashSize CreateGiven = 1 << iota
	GivenMaxElem
	GivenInitVal
	GivenBucketSize
	GivenNetmask
	GivenBitmask
	GivenTimeout
	GivenCadtFlags
	GivenPortFrom
	GivenPortTo
	GivenSize
)

func (p *CreateParams) given(g CreateGiven) bool { return p.Given&g != 0 }

// Set is one IP set. The type of the set decides how it stores its elements.
//
// +stateify savable
type Set struct {
	reg *Registry

	// name, ref, and refNetlink belong to the registry, which guards them
	// with its own lock.
	name       string
	ref        int `state:"nosave"`
	refNetlink int `state:"nosave"`

	spec     *typeSpec `state:".(string)"`
	family   uint8
	revision uint8

	// The fields below do not change after creation.
	createFlags uint32
	withTimeout bool
	withCounter bool
	withComment bool
	withSkbinfo bool
	forceadd    bool
	defTimeout  uint32
	hashSize    uint32
	maxElem     uint32
	initVal     uint32
	bucketSize  uint8
	netmask     uint8
	bitmask     Addr
	portFrom    uint16
	portTo      uint16
	listSize    uint32

	mu sync.Mutex `state:"nosave"`
	// The fields below are guarded by mu.
	store store
	list  []member
}

func (s *Set) saveSpec() string {
	if s.spec == nil {
		return ""
	}
	return s.spec.name
}

func (s *Set) loadSpec(_ context.Context, name string) {
	if spec, ok := findType(name); ok {
		s.spec = spec
	}
}

func (s *Set) afterLoad(context.Context) {
	if s.reg == nil {
		return
	}
	for _, m := range s.list {
		s.reg.GetRef(m.id)
	}
}

// newSet builds a set from the create request. It returns a negative error
// code on failure. It is ip_set_create without the registry part.
func newSet(reg *Registry, p *CreateParams) (*Set, int) {
	spec, ok := findType(p.TypeName)
	if !ok || p.Revision < spec.revisionMin || p.Revision > spec.revisionMax {
		return nil, -ErrFindType
	}
	s := &Set{
		reg:      reg,
		name:     p.Name,
		spec:     spec,
		family:   p.Family,
		revision: p.Revision,
	}
	if p.Revision == spec.revisionMax && spec.kind == kindHash {
		s.createFlags |= createFlagBucketsize
	}
	var ret int
	switch spec.kind {
	case kindHash:
		ret = s.createHash(p)
	case kindBitmapPort:
		ret = s.createBitmapPort(p)
	case kindListSet:
		ret = s.createListSet(p)
	}
	if ret != 0 {
		return nil, ret
	}
	if p.given(GivenTimeout) {
		s.withTimeout = true
		s.defTimeout = min(p.Timeout, maxTimeout)
	} else {
		s.defTimeout = NoTimeout
	}
	flags := p.CadtFlags
	s.withCounter = flags&CadtWithCounters != 0
	s.withComment = flags&CadtWithComment != 0
	s.withSkbinfo = flags&CadtWithSkbinfo != 0
	if flags&CadtWithForceadd != 0 {
		s.forceadd = true
		s.createFlags |= createFlagForceadd
	}
	s.store.init()
	return s, 0
}

// Name returns the name of the set.
func (s *Set) Name() string { return s.name }

// now returns the time of the registry clock.
func (s *Set) now() time.Duration { return s.reg.now() }

// expiredAt reports whether an expiry time has passed. The value zero marks
// an element with no timeout.
func expiredAt(expires, now time.Duration) bool {
	return expires != 0 && now >= expires
}

// timeoutToExpiry converts a timeout in seconds to an expiry time. A timeout of
// zero gives an element that never expires.
func timeoutToExpiry(seconds uint32, now time.Duration) time.Duration {
	if seconds == 0 {
		return 0
	}
	return now + time.Duration(seconds)*time.Second
}

// getExtensions reads the extension attributes of an element. It is
// ip_set_get_extensions.
func (s *Set) getExtensions(e *Element) (ext, int) {
	x := ext{timeout: s.defTimeout, packets: ^uint64(0), bytes: ^uint64(0)}
	if e.has(HasTimeout) {
		if !s.withTimeout {
			return x, -ErrTimeout
		}
		x.timeout = min(e.Timeout, maxTimeout)
	}
	if e.has(HasBytes) || e.has(HasPackets) {
		if !s.withCounter {
			return x, -ErrCounter
		}
		if e.has(HasBytes) {
			x.bytes = e.Bytes
		}
		if e.has(HasPackets) {
			x.packets = e.Packets
		}
	}
	if e.has(HasComment) {
		if !s.withComment {
			return x, -ErrComment
		}
		x.comment = e.Comment
	}
	if e.has(HasSkbMark) || e.has(HasSkbPrio) || e.has(HasSkbQueue) {
		if !s.withSkbinfo {
			return x, -ErrSkbinfo
		}
		if e.has(HasSkbMark) {
			x.skbinfo.Mark = uint32(e.SkbMark >> 32)
			x.skbinfo.MarkMask = uint32(e.SkbMark)
		}
		if e.has(HasSkbPrio) {
			x.skbinfo.Prio = e.SkbPrio
		}
		if e.has(HasSkbQueue) {
			x.skbinfo.Queue = e.SkbQueue
		}
	}
	return x, 0
}

// extensionData is the extension part of a stored element.
//
// +stateify savable
type extensionData struct {
	// expires is the expiry time. Zero means that the element never expires.
	expires        time.Duration
	packets, bytes uint64
	comment        string
	skbinfo        SkbInfo
}

// initExtensions stores the extension data of a request in an element. The
// element keeps a counter that the request does not give. It is the
// ip_set_init_* family of Linux.
func (s *Set) initExtensions(d *extensionData, x *ext, now time.Duration) {
	if s.withCounter {
		if x.bytes != ^uint64(0) {
			d.bytes = x.bytes
		}
		if x.packets != ^uint64(0) {
			d.packets = x.packets
		}
	}
	// An element that a packet adds again keeps its comment, because the packet
	// carries none.
	if s.withComment && !x.target {
		d.comment = x.comment
	}
	if s.withSkbinfo {
		d.skbinfo = x.skbinfo
	}
	if s.withTimeout {
		d.expires = timeoutToExpiry(x.timeout, now)
	}
}

// expired reports whether a stored element has timed out.
func (s *Set) expired(d *extensionData, now time.Duration) bool {
	return s.withTimeout && expiredAt(d.expires, now)
}

// matchExtensions applies the extensions of a stored element to a match from
// a packet. It updates the counters. It is ip_set_match_extensions.
func (s *Set) matchExtensions(d *extensionData, x *ext, o *KOpt, flags uint32, now time.Duration) bool {
	if s.expired(d, now) {
		return false
	}
	if s.withCounter {
		if x.packets != ^uint64(0) && flags&FlagSkipCounterUpdate == 0 {
			d.bytes += x.bytes
			d.packets += x.packets
		}
		if flags&FlagMatchCounters != 0 && o != nil &&
			!(matchCounter(d.packets, o.PacketsValue, o.PacketsOp) &&
				matchCounter(d.bytes, o.BytesValue, o.BytesOp)) {
			return false
		}
	}
	if s.withSkbinfo && o != nil {
		o.SkbInfo = d.skbinfo
	}
	return true
}

// Counter comparison operators (IPSET_COUNTER_*).
const (
	CounterNone uint8 = iota
	CounterEQ
	CounterNE
	CounterLT
	CounterGT
)

func matchCounter(counter, match uint64, op uint8) bool {
	switch op {
	case CounterNone:
		return true
	case CounterEQ:
		return counter == match
	case CounterNE:
		return counter != match
	case CounterLT:
		return counter < match
	case CounterGT:
		return counter > match
	}
	return false
}

// outputExtensions fills the extension fields of a listed element.
func (s *Set) outputExtensions(e *Element, d *extensionData, now time.Duration) {
	if s.withTimeout {
		e.Has |= HasTimeout
		if d.expires != 0 {
			remaining := uint32((d.expires - now) / time.Second)
			if remaining == 0 {
				remaining = 1
			}
			e.Timeout = remaining
		}
	}
	if s.withCounter {
		e.Has |= HasBytes | HasPackets
		e.Bytes, e.Packets = d.bytes, d.packets
	}
	if s.withComment && d.comment != "" {
		e.Has |= HasComment
		e.Comment = d.comment
	}
	if s.withSkbinfo {
		e.Has |= HasSkbMark | HasSkbPrio | HasSkbQueue
		e.SkbMark = uint64(d.skbinfo.Mark)<<32 | uint64(d.skbinfo.MarkMask)
		e.SkbPrio = d.skbinfo.Prio
		e.SkbQueue = d.skbinfo.Queue
	}
}

// Head describes the header of a set for the listing commands.
type Head struct {
	// The attributes of a hash set.
	HasHash    bool
	HashSize   uint32
	MaxElem    uint32
	Bitmask    Addr
	HasBitmask bool
	// Netmask is the prefix length of the create option netmask. It is zero
	// when the set has no such option.
	Netmask uint8
	// HasBucket is true when the header has the bucket size and the initial
	// hash value.
	HasBucket  bool
	BucketSize uint8
	InitVal    uint32

	// The attributes of a bitmap:port set.
	HasPort  bool
	PortFrom uint16
	PortTo   uint16

	// The attribute of a list:set set.
	HasSize bool
	Size    uint32

	References uint32
	MemSize    uint32
	Elements   uint32

	// HasTimeout is true when the set has the timeout extension. Timeout is
	// the default timeout in seconds.
	HasTimeout bool
	Timeout    uint32
	CadtFlags  uint32
}

// head returns the header of the set. references is the count of rules and
// of list:set sets that use the set.
func (s *Set) head(references int) Head {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := Head{References: uint32(references)}
	now := s.now()
	elements, memory := s.countLocked(now)
	h.Elements = uint32(elements)
	h.MemSize = uint32(memory)
	switch s.spec.kind {
	case kindHash:
		h.HasHash = true
		h.HashSize = s.hashSize
		h.MaxElem = s.maxElem
		// A set that has netmask 32 or 128 has no netmask. A set that has a
		// bitmask of all ones has no bitmask.
		if s.spec.bitmask && s.netmask == hostBits(s.family) && s.bitmask != prefixMask(int(hostBits(s.family)), addrSize(s.family)) {
			h.HasBitmask = true
			h.Bitmask = s.bitmask
		}
		if s.spec.netmask && s.netmask != hostBits(s.family) {
			h.Netmask = s.netmask
		}
		if s.createFlags&createFlagBucketsize != 0 {
			h.HasBucket = true
			h.BucketSize = s.bucketSize
			h.InitVal = s.initVal
		}
	case kindBitmapPort:
		h.HasPort = true
		h.PortFrom, h.PortTo = s.portFrom, s.portTo
	case kindListSet:
		h.HasSize = true
		h.Size = s.listSize
	}
	if s.withTimeout {
		h.HasTimeout = true
		h.Timeout = s.defTimeout
	}
	if s.withCounter {
		h.CadtFlags |= CadtWithCounters
	}
	if s.withComment {
		h.CadtFlags |= CadtWithComment
	}
	if s.withSkbinfo {
		h.CadtFlags |= CadtWithSkbinfo
	}
	if s.forceadd {
		h.CadtFlags |= CadtWithForceadd
	}
	return h
}

// countLocked returns the count of live elements and the estimated memory.
func (s *Set) countLocked(now time.Duration) (elements, memory int) {
	const baseSize = 128
	switch s.spec.kind {
	case kindListSet:
		for i := range s.list {
			if !s.expired(&s.list[i].ext, now) {
				elements++
			}
		}
		return elements, baseSize + 64*len(s.list)
	case kindBitmapPort:
		elements = s.store.liveCount(s, now)
		return elements, baseSize + (int(s.portTo)-int(s.portFrom)+8)/8
	}
	elements = s.store.liveCount(s, now)
	return elements, baseSize + 8*int(s.hashSize) + 64*len(s.store.entries)
}

// sameSet reports whether two sets have equal parameters, so that a CREATE
// with the flag exist for the name of the first set succeeds.
func (s *Set) sameSet(o *Set) bool {
	if s.spec != o.spec || s.family != o.family || s.defTimeout != o.defTimeout ||
		s.withTimeout != o.withTimeout || s.withCounter != o.withCounter ||
		s.withComment != o.withComment || s.withSkbinfo != o.withSkbinfo ||
		s.forceadd != o.forceadd {
		return false
	}
	switch s.spec.kind {
	case kindHash:
		// hashsize is no part of the identity: the table of Linux grows, so two
		// sets with equal contents rarely have equal sizes.
		return s.maxElem == o.maxElem &&
			s.netmask == o.netmask && s.bitmask == o.bitmask
	case kindBitmapPort:
		return s.portFrom == o.portFrom && s.portTo == o.portTo
	}
	return s.listSize == o.listSize
}

// randomInitVal returns the seed that a hash set takes when the request gives
// none.
func randomInitVal() uint32 { return rand.Uint32() }
