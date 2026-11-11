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

// Package weakmap maps pointer keys weakly and removes entries when the
// garbage collector reclaims unreachable keys.
package weakmap

import (
	"runtime"
	"sync"
	"sync/atomic"
	"weak"
)

type cleanupToken[K any] struct {
	key weak.Pointer[K]
	seq uint64
}

type entry[V any] struct {
	value   V
	cleanup runtime.Cleanup
	seq     uint64
}

// Map associates pointer keys of type *K with values of type V without
// retaining keys strongly. The zero value is ready for concurrent use.
//
// Values stored in a Map must not retain a strong pointer to their own key *K,
// or the garbage collector cannot reclaim the key.
type Map[K, V any] struct {
	mu      sync.RWMutex
	entries map[weak.Pointer[K]]entry[V]
	nextSeq uint64
	count   atomic.Int64
}

// Len returns the current number of entries in the map without locking.
func (m *Map[K, V]) Len() int {
	return int(m.count.Load())
}

// Load returns the value stored for key, or the zero value and false when key
// is nil or absent.
func (m *Map[K, V]) Load(key *K) (V, bool) {
	var zero V
	if key == nil || m.count.Load() == 0 {
		return zero, false
	}
	wk := weak.Make(key)
	m.mu.RLock()
	e, ok := m.entries[wk]
	m.mu.RUnlock()
	if !ok {
		return zero, false
	}
	return e.value, true
}

// Store sets the value for key. A nil key is ignored.
func (m *Map[K, V]) Store(key *K, value V) {
	if key == nil {
		return
	}
	wk := weak.Make(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storeLocked(key, wk, value)
}

// LoadOrStore returns the existing value for key if present. Otherwise it
// calls init under the map lock, stores the returned value, and returns that
// value with loaded set to false.
func (m *Map[K, V]) LoadOrStore(key *K, init func() V) (actual V, loaded bool) {
	if key == nil {
		if init != nil {
			return init(), false
		}
		return actual, false
	}
	if m.count.Load() > 0 {
		wk := weak.Make(key)
		m.mu.RLock()
		e, ok := m.entries[wk]
		m.mu.RUnlock()
		if ok {
			return e.value, true
		}
	}
	wk := weak.Make(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[wk]; ok {
		return e.value, true
	}
	val := init()
	m.storeLocked(key, wk, val)
	return val, false
}

// Update atomically reads the current entry for key and invokes fn under the
// map lock. When fn returns keep true, Update stores newVal; otherwise Update
// deletes any existing entry for key.
func (m *Map[K, V]) Update(key *K, fn func(old V, exists bool) (newVal V, keep bool)) {
	if key == nil {
		return
	}
	wk := weak.Make(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	oldEntry, exists := m.entries[wk]
	newVal, keep := fn(oldEntry.value, exists)
	if !keep {
		if exists {
			oldEntry.cleanup.Stop()
			delete(m.entries, wk)
			m.count.Add(-1)
		}
		return
	}
	m.storeLocked(key, wk, newVal)
}

// Delete removes the entry for key and returns its previous value and whether
// an entry was present.
func (m *Map[K, V]) Delete(key *K) (V, bool) {
	var zero V
	if key == nil || m.count.Load() == 0 {
		return zero, false
	}
	wk := weak.Make(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[wk]
	if !ok {
		return zero, false
	}
	e.cleanup.Stop()
	delete(m.entries, wk)
	m.count.Add(-1)
	return e.value, true
}

func (m *Map[K, V]) storeLocked(key *K, wk weak.Pointer[K], value V) {
	if existing, ok := m.entries[wk]; ok {
		existing.value = value
		m.entries[wk] = existing
		return
	}
	if m.entries == nil {
		m.entries = make(map[weak.Pointer[K]]entry[V])
	}
	m.nextSeq++
	seq := m.nextSeq
	c := runtime.AddCleanup(key, m.cleanupEntry, cleanupToken[K]{key: wk, seq: seq})
	m.entries[wk] = entry[V]{
		value:   value,
		cleanup: c,
		seq:     seq,
	}
	m.count.Add(1)
}

func (m *Map[K, V]) cleanupEntry(tok cleanupToken[K]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[tok.key]
	if !ok || e.seq != tok.seq {
		return
	}
	delete(m.entries, tok.key)
	m.count.Add(-1)
}
