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
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
)

func newTestSession(t *testing.T) *udpSession {
	t.Helper()
	g1, g2 := net.Pipe()
	h1, h2 := net.Pipe()
	s := &udpSession{guest: g1, host: h1, clock: newActivityClock()}
	t.Cleanup(func() {
		s.close()
		g2.Close()
		h2.Close()
	})
	return s
}

func closed(c net.Conn) bool {
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err := c.Write([]byte{0})
	return errors.Is(err, io.ErrClosedPipe)
}

func TestUDPSessionTableEvictsTheOldestSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		table := newUDPSessionTable(2)
		oldest := newTestSession(t)
		table.add(oldest)
		time.Sleep(time.Second)
		oldest.clock.touch()
		time.Sleep(time.Second)
		newer := newTestSession(t)
		table.add(newer)
		third := newTestSession(t)
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
	})
}

func TestUDPSessionTableFreesTheSlotOfARemovedSession(t *testing.T) {
	table := newUDPSessionTable(1)
	a := newTestSession(t)
	table.add(a)
	table.remove(a)
	b := newTestSession(t)
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
