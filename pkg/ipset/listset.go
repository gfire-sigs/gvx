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
	"slices"
	"time"
)

// member is one set that a list:set set holds. It holds a reference on the
// member set, by index, as the set_elem of Linux does.
//
// +stateify savable
type member struct {
	id  ID
	ext extensionData
}

// createListSet fills the list:set part of a set.
func (s *Set) createListSet(p *CreateParams) int {
	s.listSize = listDefaultSize
	if p.given(GivenSize) {
		s.listSize = p.Size
	}
	s.listSize = min(max(s.listSize, listMinSize), listMaxSize)
	return 0
}

// listSetOp is the element of a list:set operation: the member and the optional
// reference member that positions it.
type listSetOp struct {
	id    ID
	refID ID
	// before is positive for "before", negative for "after", and zero for no
	// position.
	before int
}

// listUadt runs an operation of a request on a list:set set.
func (s *Set) listUadt(adt Adt, e *Element, flags uint32) int {
	if !e.has(HasName) {
		return -ErrProtocol
	}
	x, ret := s.getExtensions(e)
	if ret != 0 {
		return ret
	}
	reg := s.reg
	op := listSetOp{refID: InvalidID}
	var sub *Set
	op.id, sub = reg.getByName(e.Name)
	if sub == nil {
		return -ErrListName
	}
	// Loop detection: a list:set set cannot hold a list:set set.
	if sub.spec.features&featureName != 0 {
		reg.put(op.id)
		return -ErrListLoop
	}
	if e.has(HasCadtFlags) && e.CadtFlags&CadtBefore != 0 {
		op.before = 1
	}
	finish := func(ret int) int {
		if op.refID != InvalidID {
			reg.put(op.refID)
		}
		if adt != AdtAdd || ret != 0 {
			reg.put(op.id)
		}
		if ret == -ErrExist && flags&FlagExist != 0 {
			return 0
		}
		return ret
	}
	if op.before != 0 && !e.has(HasNameRef) {
		return finish(-ErrListBefore)
	}
	if e.has(HasNameRef) {
		var ref *Set
		op.refID, ref = reg.getByName(e.NameRef)
		if ref == nil {
			op.refID = InvalidID
			return finish(-ErrListNameref)
		}
		if op.before == 0 {
			op.before = -1
		}
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if adt != AdtTest && s.withTimeout {
		s.cleanupMembers(now)
	}
	switch adt {
	case AdtAdd:
		ret = s.listAdd(&op, &x, flags, now)
	case AdtDel:
		ret = s.listDel(&op, now)
	default:
		ret = s.listTest(&op, now)
	}
	return finish(ret)
}

// cleanupMembers removes the members that have timed out.
//
// Preconditions: s.mu is held.
func (s *Set) cleanupMembers(now time.Duration) {
	kept := s.list[:0]
	for _, m := range s.list {
		if expiredAt(m.ext.expires, now) {
			s.reg.put(m.id)
			continue
		}
		kept = append(kept, m)
	}
	clear(s.list[len(kept):])
	s.list = kept
}

// listTest is list_set_utest.
func (s *Set) listTest(op *listSetOp, now time.Duration) int {
	var prev *member
	for i := range s.list {
		m := &s.list[i]
		if s.expired(&m.ext, now) {
			continue
		}
		if m.id != op.id {
			prev = m
			continue
		}
		switch {
		case op.before == 0:
			return 1
		case op.before > 0:
			if next := s.nextLive(i, now); next != nil && next.id == op.refID {
				return 1
			}
			return 0
		}
		if prev != nil && prev.id == op.refID {
			return 1
		}
		return 0
	}
	return 0
}

// nextLive returns the first member after position i that has not timed out.
func (s *Set) nextLive(i int, now time.Duration) *member {
	for j := i + 1; j < len(s.list); j++ {
		if !s.expired(&s.list[j].ext, now) {
			return &s.list[j]
		}
	}
	return nil
}

// lastLive returns the position of the last member that has not timed out, or
// -1 when the list has none.
func (s *Set) lastLive(now time.Duration) int {
	for i := len(s.list) - 1; i >= 0; i-- {
		if !s.expired(&s.list[i].ext, now) {
			return i
		}
	}
	return -1
}

// liveCount returns the number of members that have not timed out.
func (s *Set) liveCount(now time.Duration) int {
	n := 0
	for i := range s.list {
		if !s.expired(&s.list[i].ext, now) {
			n++
		}
	}
	return n
}

// listAdd is list_set_uadd.
func (s *Set) listAdd(op *listSetOp, x *ext, flags uint32, now time.Duration) int {
	existing, nextPos, prevPos := -1, -1, -1
	for i := range s.list {
		m := &s.list[i]
		switch {
		case s.expired(&m.ext, now):
		case m.id == op.id:
			existing = i
		case op.before == 0 || m.id != op.refID:
		case op.before > 0:
			nextPos = i
		default:
			prevPos = i
		}
	}
	if (op.before > 0 && nextPos < 0) || (op.before < 0 && prevPos < 0) {
		return -ErrListRefExist
	}
	if existing >= 0 {
		if flags&FlagExist == 0 {
			return -ErrExist
		}
		s.list[existing].ext = extensionData{}
		s.initExtensions(&s.list[existing].ext, x, now)
		// The set is already in the list: drop the extra reference.
		s.reg.put(op.id)
		return 0
	}
	if s.liveCount(now) >= int(s.listSize) {
		// The list is full. Without forceadd the add fails. With forceadd the
		// last member leaves the list, as the push-out of Linux does. The
		// reference member stays, because the new member needs its position.
		victim := s.lastLive(now)
		if !s.forceadd || victim < 0 || victim == nextPos || victim == prevPos {
			return -ErrListFull
		}
		s.reg.put(s.list[victim].id)
		s.list = slices.Delete(s.list, victim, victim+1)
	}
	m := member{id: op.id}
	s.initExtensions(&m.ext, x, now)
	switch {
	case op.before == 0:
		s.list = append(s.list, m)
	case op.before > 0:
		// Before the reference member.
		s.list = slices.Insert(s.list, nextPos, m)
	default:
		// After the reference member.
		s.list = slices.Insert(s.list, prevPos+1, m)
	}
	return 0
}

// listDel is list_set_udel.
func (s *Set) listDel(op *listSetOp, now time.Duration) int {
	var prev *member
	for i := range s.list {
		m := &s.list[i]
		if s.expired(&m.ext, now) {
			continue
		}
		if m.id != op.id {
			prev = m
			continue
		}
		if op.before > 0 {
			if i+1 >= len(s.list) || s.list[i+1].id != op.refID {
				return -ErrListRefExist
			}
		} else if op.before < 0 {
			if prev == nil || prev.id != op.refID {
				return -ErrListRefExist
			}
		}
		s.reg.put(m.id)
		s.list = slices.Delete(s.list, i, i+1)
		return 0
	}
	if op.before != 0 {
		return -ErrListRefExist
	}
	return -ErrExist
}

// listKadt runs an operation of a packet on the members of a list:set set.
func (s *Set) listKadt(adt Adt, pkt *Packet, o *KOpt) int {
	now := s.now()
	s.mu.Lock()
	ids := make([]ID, 0, len(s.list))
	for i := range s.list {
		if !s.expired(&s.list[i].ext, now) {
			ids = append(ids, s.list[i].id)
		}
	}
	s.mu.Unlock()
	switch adt {
	case AdtTest:
		return s.listKtest(ids, pkt, o, now)
	case AdtAdd:
		// The first member that accepts the element wins.
		for _, id := range ids {
			if s.reg.Add(id, pkt, o) == 0 {
				return 0
			}
		}
		return 0
	case AdtDel:
		for _, id := range ids {
			if s.reg.Del(id, pkt, o) == 0 {
				return 0
			}
		}
		return 0
	}
	return -errnoEINVAL
}

// listKtest is list_set_ktest. It tests the members in order and applies the
// extensions of the list:set set to the first member that matches.
func (s *Set) listKtest(ids []ID, pkt *Packet, o *KOpt, now time.Duration) int {
	sub := *o
	sub.CmdFlags &^= FlagMatchCounters
	if sub.CmdFlags&FlagSkipSubcounterUpdte != 0 {
		sub.CmdFlags |= FlagSkipCounterUpdate
	}
	x := ext{timeout: o.timeoutOr(s.defTimeout), packets: 1, bytes: uint64(pkt.Len), target: true}
	for _, id := range ids {
		if s.reg.Test(id, pkt, &sub) <= 0 {
			continue
		}
		// The member that matched gives its packet information. The list
		// overwrites it when the list stores its own.
		o.SkbInfo = sub.SkbInfo
		s.mu.Lock()
		hit := false
		for i := range s.list {
			if s.list[i].id == id {
				hit = s.matchExtensions(&s.list[i].ext, &x, o, o.CmdFlags, now)
				break
			}
		}
		s.mu.Unlock()
		if hit {
			return 1
		}
	}
	return 0
}

// listElement builds the listed form of a member.
func (s *Set) listElement(m *member, now time.Duration) Element {
	name, _ := s.reg.NameByIndex(m.id)
	out := Element{Has: HasName, Name: name}
	s.outputExtensions(&out, &m.ext, now)
	return out
}

// flushMembers removes every member and drops the references.
func (s *Set) flushMembers() {
	s.mu.Lock()
	list := s.list
	s.list = nil
	s.mu.Unlock()
	for _, m := range list {
		s.reg.put(m.id)
	}
}
