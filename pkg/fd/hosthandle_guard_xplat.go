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

package fd

import (
	"sync"
	"sync/atomic"
)

// handleGuard keeps the OS handle of a HostHandle open while a call uses it.
//
// A call that reads the raw handle and then closes or reads it later can race
// with Close. The OS can give the closed number to a new file or socket, and
// the late call then reads or writes an unrelated object. A call therefore
// enters the guard before it reads the raw handle and leaves the guard after
// the system call returns. shut waits until every such call left, so the
// close of the OS handle never overlaps a call that uses it. After shut starts,
// no new call enters.
//
// The wait is bounded by one system call. Every HostHandle wraps a regular
// file that OpenHostPath opened (an EROFS layer image), and ReadAt, WriteAt,
// and Dup never block on such a file. No call closes its own handle. A handle
// of a pipe, a socket, or a console must not use HostHandle, because its calls
// can block for ever and Close would wait for them.
//
// The first shut owns the close or the release of the OS handle and ends it
// with finish. A later shut waits for finish, so a second Close never returns
// before the OS handle is closed.
//
// The zero value is ready to use.
type handleGuard struct {
	mu       sync.Mutex
	idle     sync.Cond
	active   int
	finished bool
	closed   atomic.Bool
}

// isClosed reports whether shut started.
func (g *handleGuard) isClosed() bool { return g.closed.Load() }

// enter admits one call. It returns false when shut started. A true result
// obliges the caller to call exit.
func (g *handleGuard) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed.Load() {
		return false
	}
	g.active++
	return true
}

// exit ends a call that enter admitted.
func (g *handleGuard) exit() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active--
	if g.active == 0 && g.closed.Load() {
		g.idle.Broadcast()
	}
}

// shut stops the admission of new calls and waits for the admitted calls to
// exit. It returns true for the first call, which owns the close or the
// release of the OS handle and must call finish when it is done. Any later
// call waits for finish and returns false.
func (g *handleGuard) shut() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.idle.L == nil {
		g.idle.L = &g.mu
	}
	if g.closed.Swap(true) {
		for !g.finished {
			g.idle.Wait()
		}
		return false
	}
	for g.active > 0 {
		g.idle.Wait()
	}
	return true
}

// finish ends the close or the release that the first shut owns.
func (g *handleGuard) finish() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.finished = true
	g.idle.Broadcast()
}
