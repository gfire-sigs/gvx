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
	"sync"
	"sync/atomic"
	"time"
)

// Module holds the module parameters of ip_set. The parameter max_sets sets
// the initial size of the table of sets of each network namespace that is
// created after the change. The table grows as in Linux, so the parameter is
// no limit on the count of sets.
type Module struct {
	maxSets atomic.Int32
}

// NewModule returns the parameters with the defaults of Linux.
func NewModule() *Module {
	m := &Module{}
	m.maxSets.Store(DefaultMaxSets)
	return m
}

// MaxSets returns the parameter max_sets.
func (m *Module) MaxSets() int { return int(m.maxSets.Load()) }

// SetMaxSets sets the parameter max_sets. A registry that starts later uses a
// table of this size, or of the default size for zero, and the largest table
// size for a value above it. The value stays as written.
func (m *Module) SetMaxSets(n int32) {
	m.maxSets.Store(max(n, 0))
}

// Registry holds the sets of one network namespace. Its methods are safe for
// concurrent use.
type Registry struct {
	clock func() time.Duration

	// mu guards the table and the reference counts and names of the sets.
	// A method never holds mu while it calls into a Set that takes the
	// lock of the Set, except where a comment says so.
	mu   sync.RWMutex
	sets []*Set
}

// NewRegistry returns a registry with a table of maxSets slots. clock returns
// a monotonic time.
func NewRegistry(maxSets int, clock func() time.Duration) *Registry {
	if maxSets <= 0 {
		maxSets = DefaultMaxSets
	}
	maxSets = min(maxSets, int(InvalidID)-1)
	return &Registry{clock: clock, sets: make([]*Set, maxSets)}
}

// find returns the set with the name and its index.
//
// Preconditions: r.mu is held.
func (r *Registry) find(name string) (ID, *Set) {
	for i, s := range r.sets {
		if s != nil && s.name == name {
			return ID(i), s
		}
	}
	return InvalidID, nil
}

// Create creates a set. It is ip_set_create.
func (r *Registry) Create(p *CreateParams) error {
	s, ret := newSet(r, p)
	if ret != 0 {
		return errCode(ret)
	}
	r.mu.Lock()
	var free = -1
	var clash *Set
	for i, o := range r.sets {
		switch {
		case o == nil:
			if free < 0 {
				free = i
			}
		case o.name == p.Name:
			clash = o
		}
		if clash != nil {
			break
		}
	}
	if clash != nil {
		r.mu.Unlock()
		if p.Exist && clash.sameSet(s) {
			return nil
		}
		return &Error{Code: errnoEEXIST}
	}
	if free < 0 {
		// The table is full: grow it by one step. The index is 16 bits wide
		// and the step wraps, as in Linux.
		next := uint16(len(r.sets)) + setIncrement
		if next < uint16(len(r.sets)) || ID(next) == InvalidID {
			r.mu.Unlock()
			return &Error{Code: ErrMaxSets}
		}
		grown := make([]*Set, next)
		copy(grown, r.sets)
		free = len(r.sets)
		r.sets = grown
	}
	r.sets[free] = s
	r.mu.Unlock()
	return nil
}

// Destroy destroys the set with the name, or every set when all is true. A set
// that a rule, a list:set set, or a listing references fails with the busy
// error. With exist, a missing set is no error.
func (r *Registry) Destroy(name string, all, exist bool) error {
	r.mu.Lock()
	var doomed []*Set
	if all {
		for _, s := range r.sets {
			if s != nil && (s.ref != 0 || s.refNetlink != 0) {
				r.mu.Unlock()
				return &Error{Code: ErrBusy}
			}
		}
		for i, s := range r.sets {
			if s != nil {
				doomed = append(doomed, s)
				r.sets[i] = nil
			}
		}
	} else {
		id, s := r.find(name)
		switch {
		case s == nil:
			r.mu.Unlock()
			if exist {
				return nil
			}
			return &Error{Code: errnoENOENT}
		case s.ref != 0 || s.refNetlink != 0:
			r.mu.Unlock()
			return &Error{Code: ErrBusy}
		}
		doomed = append(doomed, s)
		r.sets[id] = nil
	}
	r.mu.Unlock()
	for _, s := range doomed {
		s.flush()
	}
	return nil
}

// Flush removes the elements of the set with the name, or of every set when
// all is true.
func (r *Registry) Flush(name string, all bool) error {
	r.mu.RLock()
	var targets []*Set
	if all {
		for _, s := range r.sets {
			if s != nil {
				targets = append(targets, s)
			}
		}
	} else {
		_, s := r.find(name)
		if s == nil {
			r.mu.RUnlock()
			return &Error{Code: errnoENOENT}
		}
		targets = append(targets, s)
	}
	r.mu.RUnlock()
	for _, s := range targets {
		s.flush()
	}
	return nil
}

// Rename gives a set a new name.
func (r *Registry) Rename(from, to string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, s := r.find(from)
	if s == nil {
		return &Error{Code: errnoENOENT}
	}
	if s.ref != 0 || s.refNetlink != 0 {
		return &Error{Code: ErrReferenced}
	}
	if _, other := r.find(to); other != nil {
		return &Error{Code: ErrExistSetname2}
	}
	s.name = to
	return nil
}

// Swap exchanges two sets, so that each name and index points to the other
// set. The reference counts and the names swap too, so that the rules that
// name an index see the other data.
func (r *Registry) Swap(a, b string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	fromID, from := r.find(a)
	if from == nil {
		return &Error{Code: errnoENOENT}
	}
	toID, to := r.find(b)
	if to == nil {
		return &Error{Code: ErrExistSetname2}
	}
	if from.spec.features != to.spec.features || from.family != to.family {
		return &Error{Code: ErrTypeMismatch}
	}
	if from.refNetlink != 0 || to.refNetlink != 0 {
		return &Error{Code: errnoEBUSY}
	}
	from.name, to.name = to.name, from.name
	from.ref, to.ref = to.ref, from.ref
	r.sets[fromID], r.sets[toID] = to, from
	return nil
}

// Lookup returns the index and family of the set with the name.
func (r *Registry) Lookup(name string) (id ID, family uint8, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, s := r.find(name)
	if s == nil {
		return InvalidID, 0, false
	}
	return id, s.family, true
}

// SetInfo is the identity of a set for the HEADER command and the listing.
type SetInfo struct {
	Name     string
	TypeName string
	Family   uint8
	Revision uint8
	Index    ID
}

// Info returns the identity of the set with the name.
func (r *Registry) Info(name string) (SetInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, s := r.find(name)
	if s == nil {
		return SetInfo{}, &Error{Code: errnoENOENT}
	}
	return s.info(id), nil
}

func (s *Set) info(id ID) SetInfo {
	return SetInfo{Name: s.name, TypeName: s.spec.name, Family: s.family, Revision: s.revision, Index: id}
}

// NameByIndex returns the name of the set at the index.
func (r *Registry) NameByIndex(id ID) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if int(id) >= len(r.sets) || r.sets[id] == nil {
		return "", false
	}
	return r.sets[id].name, true
}

// Len returns the size of the table of sets, ip_set_max of Linux.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sets)
}

// setByID returns the set at the index, or nil.
func (r *Registry) setByID(id ID) *Set {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if int(id) >= len(r.sets) {
		return nil
	}
	return r.sets[id]
}

// getByName finds a set by name and counts one more reference to it, as
// ip_set_get_byname does.
func (r *Registry) getByName(name string) (ID, *Set) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, s := r.find(name)
	if s != nil {
		s.ref++
	}
	return id, s
}

// put drops one reference to the set at the index.
func (r *Registry) put(id ID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if int(id) < len(r.sets) && r.sets[id] != nil && r.sets[id].ref > 0 {
		r.sets[id].ref--
	}
}

// GetRef counts one more reference to the set at the index, for a rule that
// names the set. It reports false when no set has the index. It is
// ip_set_nfnl_get_byindex.
func (r *Registry) GetRef(id ID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if int(id) >= len(r.sets) || r.sets[id] == nil {
		return false
	}
	r.sets[id].ref++
	return true
}

// PutRef drops the reference that GetRef took. It is ip_set_nfnl_put.
func (r *Registry) PutRef(id ID) { r.put(id) }

// Uadt runs an operation of a request on the set with the name. It returns
// the code of uadt: negative for an error, and for TEST positive when the
// element is in the set.
func (r *Registry) Uadt(name string, adt Adt, e *Element, flags uint32) int {
	r.mu.RLock()
	_, s := r.find(name)
	r.mu.RUnlock()
	if s == nil {
		return -errnoENOENT
	}
	return s.uadt(adt, e, flags)
}

// Family returns the family of the set with the name. The netlink layer needs
// it to parse the addresses of an element.
func (r *Registry) Family(name string) (uint8, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, s := r.find(name)
	if s == nil {
		return 0, false
	}
	return s.family, true
}

// uadt dispatches an operation of a request to the type of the set.
func (s *Set) uadt(adt Adt, e *Element, flags uint32) int {
	switch s.spec.kind {
	case kindHash:
		return s.hashUadt(adt, e, flags)
	case kindBitmapPort:
		return s.bitmapUadt(adt, e, flags)
	}
	return s.listUadt(adt, e, flags)
}

// flush removes every element of the set.
func (s *Set) flush() {
	if s.spec.kind == kindListSet {
		s.flushMembers()
		return
	}
	s.mu.Lock()
	s.store.flush()
	s.mu.Unlock()
}
