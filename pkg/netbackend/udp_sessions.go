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

// An in-flight send keeps both directions alive, including time spent waiting for bandwidth.
type activityClock struct {
	mu      sync.Mutex
	last    time.Time
	pending int
	stopped bool
	ctx     context.Context
	cancel  context.CancelFunc
}

func newActivityClock() *activityClock {
	return &activityClock{last: time.Now()}
}

func (c *activityClock) beginSend() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return false
	}
	c.pending++
	return true
}

func (c *activityClock) finishSend(attempted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending--
	if attempted {
		c.last = time.Now()
	}
}

func (c *activityClock) sendContext(ctx context.Context) (context.Context, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return nil, false
	}
	if c.ctx == nil {
		c.ctx, c.cancel = context.WithCancel(ctx)
	}
	return c.ctx, true
}

func (c *activityClock) deadline(idle time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline := c.last.Add(idle)
	if c.pending != 0 {
		if now := time.Now(); !now.Before(deadline) {
			return now.Add(idle)
		}
	}
	return deadline
}

func (c *activityClock) expire(idle time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped && c.pending == 0 && time.Since(c.last) >= idle {
		c.stopped = true
	}
	return c.stopped
}

func (c *activityClock) stop() {
	c.mu.Lock()
	c.stopped = true
	cancel := c.cancel
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *activityClock) lastActivity() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.pending != 0
}

func sendRelayDatagram(ctx context.Context, clock *activityClock, shaper *BandwidthShaper, dir BandwidthDirection, n int, write func() (int, error)) error {
	if !shaper.Enabled(dir) {
		_, err := write()
		return err
	}
	sendCtx, ok := clock.sendContext(ctx)
	if !ok {
		return net.ErrClosed
	}
	_, err := shaper.ShapeDatagram(sendCtx, dir, n, write)
	if sendCtx.Err() != nil {
		return net.ErrClosed
	}
	return err
}

// udpSession is one relayed UDP flow of the guest.
type udpSession struct {
	guest, host net.Conn
	clock       *activityClock
}

func (s *udpSession) close() {
	s.clock.stop()
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
	var pending bool
	t.mu.Lock()
	if len(t.sessions) >= t.max {
		for c := range t.sessions {
			last, inFlight := c.clock.lastActivity()
			if victim == nil || (pending && !inFlight) || (pending == inFlight && last.Before(oldest)) {
				victim, oldest, pending = c, last, inFlight
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
