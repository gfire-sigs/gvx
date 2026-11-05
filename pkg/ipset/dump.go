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

// Cursor reads the elements of one set in order. A set that has a Cursor
// cannot be destroyed or swapped, because the Dump that made the Cursor pins
// the set. Elements that an add creates after the Cursor started do not
// appear. An element that exists for the whole life of the Cursor appears
// once.
type Cursor struct {
	set  *Set
	pos  int
	end  int
	next int
	open bool
}

// newCursor starts a listing of the elements of the set.
func (s *Set) newCursor() *Cursor {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &Cursor{set: s, open: true}
	if s.spec.kind == kindListSet {
		c.end = len(s.list)
	} else {
		c.end = len(s.store.entries)
		s.store.listings++
	}
	return c
}

// Peek returns the element at the position of the Cursor. It reports false at
// the end. The position stays until Advance.
func (c *Cursor) Peek() (Element, bool) {
	s := c.set
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.spec.kind == kindListSet {
		for i := c.pos; i < min(c.end, len(s.list)); i++ {
			m := &s.list[i]
			if s.expired(&m.ext, now) {
				continue
			}
			c.next = i + 1
			return s.listElement(m, now), true
		}
		return Element{}, false
	}
	for i := c.pos; i < min(c.end, len(s.store.entries)); i++ {
		e := &s.store.entries[i]
		if !e.live || s.expired(&e.extensionData, now) {
			continue
		}
		c.next = i + 1
		if s.spec.kind == kindBitmapPort {
			return s.bitmapElement(e, now), true
		}
		return s.hashElement(e, now), true
	}
	return Element{}, false
}

// Advance moves the Cursor past the element that Peek returned.
func (c *Cursor) Advance() { c.pos = c.next }

// Close ends the listing.
func (c *Cursor) Close() {
	if !c.open {
		return
	}
	c.open = false
	s := c.set
	if s.spec.kind == kindListSet {
		return
	}
	s.mu.Lock()
	s.store.listings--
	if s.store.listings == 0 {
		s.store.compact()
	}
	s.mu.Unlock()
}

// Dump lists the sets of a registry in the order of Linux: every set in the
// order of its index, with the list:set sets last.
type Dump struct {
	reg *Registry
	// one is true when the dump lists the set at oneID only.
	one   bool
	oneID ID
	// last is true during the second pass over the list:set sets.
	last  bool
	index int
	// done is true after the last set.
	done bool

	cur    *Set
	curID  ID
	cursor *Cursor
}

// NewDump starts a listing. With one, it lists the set with the name, or fails
// with ENOENT when no such set exists. Otherwise it lists every set.
func (r *Registry) NewDump(name string, one bool) (*Dump, error) {
	d := &Dump{reg: r, one: one}
	if one {
		r.mu.RLock()
		id, s := r.find(name)
		r.mu.RUnlock()
		if s == nil {
			return nil, &Error{Code: errnoENOENT}
		}
		d.oneID = id
	}
	return d, nil
}

// Next pins the next set of the listing and returns its identity and its
// header. It reports false after the last set. The caller reads the elements
// through Cursor and then calls Release.
func (d *Dump) Next() (SetInfo, Head, bool, error) {
	if d.cur != nil {
		d.Release()
	}
	r := d.reg
	r.mu.Lock()
	for !d.done {
		if d.one {
			d.done = true
			s := r.setAt(d.oneID)
			if s == nil {
				r.mu.Unlock()
				return SetInfo{}, Head{}, false, &Error{Code: errnoENOENT}
			}
			return d.pin(s, d.oneID)
		}
		if d.index >= len(r.sets) {
			if d.last {
				d.done = true
				break
			}
			d.last, d.index = true, 0
			continue
		}
		i := d.index
		d.index++
		s := r.sets[i]
		if s == nil || (s.spec.features&featureDumpLast != 0) != d.last {
			continue
		}
		return d.pin(s, ID(i))
	}
	r.mu.Unlock()
	return SetInfo{}, Head{}, false, nil
}

// setAt returns the set at the index, or nil.
//
// Preconditions: r.mu is held.
func (r *Registry) setAt(id ID) *Set {
	if int(id) >= len(r.sets) {
		return nil
	}
	return r.sets[id]
}

// pin counts a listing reference on the set and releases the lock of the
// registry.
//
// Preconditions: d.reg.mu is held for writing. pin releases it.
func (d *Dump) pin(s *Set, id ID) (SetInfo, Head, bool, error) {
	s.refNetlink++
	references := s.ref
	info := s.info(id)
	d.reg.mu.Unlock()
	d.cur, d.curID = s, id
	head := s.head(references)
	d.cursor = s.newCursor()
	return info, head, true, nil
}

// Cursor returns the cursor over the elements of the set that Next returned.
func (d *Dump) Cursor() *Cursor { return d.cursor }

// Release unpins the set that Next returned.
func (d *Dump) Release() {
	if d.cur == nil {
		return
	}
	d.cursor.Close()
	d.reg.mu.Lock()
	if d.cur.refNetlink > 0 {
		d.cur.refNetlink--
	}
	d.reg.mu.Unlock()
	d.cur, d.cursor = nil, nil
}

// Close ends the listing and unpins its set.
func (d *Dump) Close() {
	d.Release()
	d.done = true
}
