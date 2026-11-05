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
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
)

// newTestSession returns a session over two pipes. Its clock shows activity at
// the offset from the start of the clock.
func newTestSession(t *testing.T, active time.Duration) *udpSession {
	g1, g2 := net.Pipe()
	h1, h2 := net.Pipe()
	t.Cleanup(func() { g2.Close(); h2.Close() })
	s := &udpSession{guest: g1, host: h1, clock: newActivityClock()}
	s.clock.last.Store(int64(active))
	return s
}

func closed(c net.Conn) bool {
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err := c.Write([]byte{0})
	return errors.Is(err, io.ErrClosedPipe)
}

func TestUDPSessionTableEvictsTheOldestSession(t *testing.T) {
	table := newUDPSessionTable(2)
	oldest := newTestSession(t, 1*time.Second)
	newer := newTestSession(t, 5*time.Second)
	table.add(newer)
	table.add(oldest)
	third := newTestSession(t, 9*time.Second)
	table.add(third)
	if table.len() != 2 {
		t.Fatalf("len = %d, want 2", table.len())
	}
	if !closed(oldest.guest) || !closed(oldest.host) {
		t.Error("the session with the oldest datagram stays open")
	}
	if closed(newer.guest) || closed(third.guest) {
		t.Error("a newer session was closed")
	}
}

func TestUDPSessionTableFreesTheSlotOfARemovedSession(t *testing.T) {
	table := newUDPSessionTable(1)
	a := newTestSession(t, time.Second)
	table.add(a)
	table.remove(a)
	b := newTestSession(t, 2*time.Second)
	table.add(b)
	if closed(b.guest) || table.len() != 1 {
		t.Errorf("len = %d, closed = %v; want 1 session and no eviction after a removal", table.len(), closed(b.guest))
	}
}

func TestNATSessionLimitComesFromTheTunables(t *testing.T) {
	s, fwd, err := NewNATStack(NATConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fwd.Close(); s.Close() }()
	if got, want := fwd.udpSessions.max, tuning.NATUDPSessions; got != (tuning.Values{}).Int(want) || got != 512 {
		t.Errorf("default session limit = %d, want 512", got)
	}
	tuned, err := tuning.Values{}.WithInt(tuning.NATUDPSessions, 7)
	if err != nil {
		t.Fatal(err)
	}
	s2, fwd2, err := NewNATStack(NATConfig{Tuning: tuned})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fwd2.Close(); s2.Close() }()
	if got := fwd2.udpSessions.max; got != 7 {
		t.Errorf("tuned session limit = %d, want 7", got)
	}
}

func TestNATLinkHasTheMTUOfAnEthernetLink(t *testing.T) {
	s, fwd, err := NewNATStack(NATConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fwd.Close(); s.Close() }()
	nics := s.NICInfo()
	if got := nics[Eth0NICID].MTU; got != 1500 {
		t.Errorf("eth0 MTU = %d, want 1500", got)
	}
	if got := nics[LoopbackNICID].MTU; got != 65536 {
		t.Errorf("lo MTU = %d, want 65536", got)
	}
}
