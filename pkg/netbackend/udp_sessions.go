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

package netbackend

import (
	"net"
	"sync"
)

// defaultMaxUDPSessions is the largest count of NAT UDP sessions that live at
// once when NATConfig sets no limit. A session holds one host socket and one
// goroutine for each direction. Each direction also holds one read buffer of
// 64 KiB while it runs, so the buffers of a full table take 64 MiB.
const defaultMaxUDPSessions = 512

// udpSession is one relayed UDP flow of the guest.
type udpSession struct {
	guest, host net.Conn
	clock       *activityClock
}

func (s *udpSession) close() {
	_ = s.guest.Close()
	_ = s.host.Close()
}

// udpSessionTable bounds the count of live UDP sessions. When the table is full,
// a new session evicts the session with the oldest datagram, so a guest that
// opens flows from many source ports, as a VXLAN tunnel with a flow hash does,
// cannot exhaust the file descriptors or the memory of the host.
type udpSessionTable struct {
	max int

	mu       sync.Mutex
	sessions map[*udpSession]struct{}
}

func newUDPSessionTable(max int) *udpSessionTable {
	if max <= 0 {
		max = defaultMaxUDPSessions
	}
	return &udpSessionTable{max: max, sessions: make(map[*udpSession]struct{})}
}

// add registers the session. It closes the least recently active session first
// when the table is full.
func (t *udpSessionTable) add(s *udpSession) {
	var victim *udpSession
	t.mu.Lock()
	if len(t.sessions) >= t.max {
		for c := range t.sessions {
			if victim == nil || c.clock.last.Load() < victim.clock.last.Load() {
				victim = c
			}
		}
		delete(t.sessions, victim)
	}
	t.sessions[s] = struct{}{}
	t.mu.Unlock()
	if victim != nil {
		victim.close()
	}
}

// remove unregisters the session.
func (t *udpSessionTable) remove(s *udpSession) {
	t.mu.Lock()
	delete(t.sessions, s)
	t.mu.Unlock()
}

// len returns the count of live sessions.
func (t *udpSessionTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}
