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
	"context"
	"net"
	"sync"
	"time"
)

// activityClock tracks both directions of a UDP session. If the timer fires
// with work pending, it stays disarmed until the last item settles.
type activityClock struct {
	mu      sync.Mutex
	last    time.Time
	pending int
	closed  bool

	idle           time.Duration
	timer          *time.Timer
	waitingForWork bool
	cancel         context.CancelFunc
}

func newActivityClock() *activityClock {
	return &activityClock{last: time.Now()}
}

func (c *activityClock) lastActivity() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// touch records unshaped traffic. It cannot revive an expired session.
func (c *activityClock) touch() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.last = time.Now()
	return true
}

// accept holds off idle expiry from queue admission through final settlement.
func (c *activityClock) accept() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.last = time.Now()
	c.pending++
	return true
}

func (c *activityClock) settle(delivered bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending--
	if c.closed {
		return
	}
	if delivered {
		// A paced write may have waited longer than idle. Give its reply
		// the same idle window as a datagram that was sent immediately.
		c.last = time.Now()
	}
	if c.pending == 0 && c.waitingForWork {
		c.waitingForWork = false
		c.timer.Reset(time.Until(c.last.Add(c.idle)))
	}
}

func (c *activityClock) startIdleTimer(idle time.Duration, expire func(), cancel context.CancelFunc) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return
	}
	defer c.mu.Unlock()
	c.cancel = cancel
	c.idle = idle
	c.timer = time.AfterFunc(time.Until(c.last.Add(idle)), func() {
		c.mu.Lock()
		switch {
		case c.closed:
		case c.pending != 0:
			c.waitingForWork = true
		default:
			if wait := time.Until(c.last.Add(idle)); wait > 0 {
				c.timer.Reset(wait)
				break
			}
			c.closed = true
			c.mu.Unlock()
			expire()
			return
		}
		c.mu.Unlock()
	})
}

func (c *activityClock) stop() int {
	c.mu.Lock()
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	cancel, pending := c.cancel, c.pending
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return pending
}

// udpSession is one relayed UDP flow of the guest.
type udpSession struct {
	guest, host net.Conn
	clock       *activityClock
	policy      *NATPolicy
}

func (s *udpSession) close() {
	if s.clock.stop() != 0 && s.policy != nil {
		s.policy.cancelDatagrams(s.clock)
	}
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

// newUDPSessionTable returns a table for at most max live sessions. A session
// holds one host socket and one goroutine for each direction. Each direction
// also holds one read buffer of 64 KiB while it runs.
func newUDPSessionTable(max int) *udpSessionTable {
	return &udpSessionTable{max: max, sessions: make(map[*udpSession]struct{})}
}

// add registers the session. It closes the least recently active session first
// when the table is full.
func (t *udpSessionTable) add(s *udpSession) {
	var victim *udpSession
	var oldest time.Time
	t.mu.Lock()
	if len(t.sessions) >= t.max {
		for c := range t.sessions {
			last := c.clock.lastActivity()
			if victim == nil || last.Before(oldest) {
				victim, oldest = c, last
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
