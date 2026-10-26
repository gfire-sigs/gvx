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

package ext4lite

import "sync"

// The flush must write a state that never existed half done. One guest
// operation changes the allocator and one or more nodes in several steps. A
// snapshot between two steps would show a block that a file names but the
// bitmap calls free, and a crash would then hand that block to a second file.
//
// The gate makes the snapshot a cut between operations. Every operation that
// can change the allocator, or that links several nodes, enters the gate first.
// A change of one field of one node, such as an access time, needs no entry:
// the node lock orders it with the copy, and either state is consistent. The
// flush closes the gate, waits until no operation runs, copies the state, and
// opens the gate again. The disk writes of the flush happen after the gate
// opens.
//
// A plain read-write lock cannot serve here. An operation can call code that
// also enters the gate, for example when a last reference drops inside an
// unlink. A second read lock request that waits for a pending writer would
// deadlock with the first one. The gate splits the entries in two kinds:
//
//   - enterOp is for the first entry of a guest operation. It waits while the
//     flush drains or copies.
//   - enterInner is for every other entry. When another entry is active, the
//     caller is a nested call or a parallel operation that the flush already
//     waits for, so it never waits. When no entry is active, the caller starts
//     fresh work and waits for the flush like enterOp.

// opGate coordinates guest operations with the snapshot of the flush.
type opGate struct {
	mu   sync.Mutex
	cond *sync.Cond
	// active counts the entries that did not exit yet.
	active int
	// draining is set while the flush waits for the active entries.
	draining bool
	// copying is set while the flush copies the state.
	copying bool
}

func (g *opGate) init() { g.cond = sync.NewCond(&g.mu) }

// enterOp starts a guest operation. The caller calls exit once.
func (g *opGate) enterOp() {
	g.mu.Lock()
	for g.draining || g.copying {
		g.cond.Wait()
	}
	g.active++
	g.mu.Unlock()
}

// enterInner starts work that can run inside another operation. The caller
// calls exit once.
func (g *opGate) enterInner() {
	g.mu.Lock()
	for g.active == 0 && (g.draining || g.copying) {
		g.cond.Wait()
	}
	g.active++
	g.mu.Unlock()
}

// exit ends an entry.
func (g *opGate) exit() {
	g.mu.Lock()
	g.active--
	if g.active == 0 {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}

// closeForCopy waits until no entry is active and keeps new entries out. The
// flush calls openAfterCopy when it finishes the copy.
func (g *opGate) closeForCopy() {
	g.mu.Lock()
	g.draining = true
	for g.active > 0 {
		g.cond.Wait()
	}
	g.draining = false
	g.copying = true
	g.mu.Unlock()
}

// openAfterCopy lets the waiting entries run.
func (g *opGate) openAfterCopy() {
	g.mu.Lock()
	g.copying = false
	g.cond.Broadcast()
	g.mu.Unlock()
}

// held reports whether a caller may change the allocator now: an entry is
// active, or the flush copies the state.
func (g *opGate) held() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active > 0 || g.copying
}
