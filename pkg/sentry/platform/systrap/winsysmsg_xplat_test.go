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

//go:build (darwin || windows) && (amd64 || arm64)

package systrap

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

func TestWinSysmsgHeaderLayout(t *testing.T) {
	var h winSysmsgHeader
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"State", unsafe.Offsetof(h.State), winOffState},
		{"SentryWaiter", unsafe.Offsetof(h.SentryWaiter), winOffSentryWaiter},
		{"StubWaiter", unsafe.Offsetof(h.StubWaiter), winOffStubWaiter},
		{"GuestEvent", unsafe.Offsetof(h.GuestEvent), winOffGuestEvent},
		{"HostEvent", unsafe.Offsetof(h.HostEvent), winOffHostEvent},
		{"NtSetEvent", unsafe.Offsetof(h.NtSetEvent), winOffNtSetEvent},
		{"NtWaitForSingleObject", unsafe.Offsetof(h.NtWaitForSingleObject), winOffNtWait},
		{"Tail", unsafe.Offsetof(h.Tail), winOffTail},
		{"Target", unsafe.Offsetof(h.Target), winOffTarget},
		{"TLS", unsafe.Offsetof(h.TLS), winOffTLS},
		{"SpinTicks", unsafe.Offsetof(h.SpinTicks), winOffSpinTicks},
		{"size", unsafe.Sizeof(h), winOffRegs},
	} {
		if c.got != c.want {
			t.Errorf("offset of %s is %#x, the spill routine uses %#x", c.name, c.got, c.want)
		}
	}
}

// testSpinPolls is the spin window of the Sentry in the tests, in polls.
const testSpinPolls = 512

func TestWinSysmsgFitsItsPage(t *testing.T) {
	if got := unsafe.Sizeof(winSysmsg{}); got > winSysmsgSize {
		t.Fatalf("winSysmsg has %#x bytes, the page holds %#x", got, winSysmsgSize)
	}
	if winStubStackTop%16 != 0 || winStubStackTop > winThreadMapSize {
		t.Fatalf("stub stack top %#x is not aligned or lies outside the mapped area", winStubStackTop)
	}
	if winArenaSize%0x10000 != 0 {
		t.Fatalf("arena size %#x is not a multiple of the 64KB allocation granularity", uint64(winArenaSize))
	}
	if winSpillOffset >= winCodeSize {
		t.Fatalf("spill offset %#x lies outside the code pages of %#x bytes", winSpillOffset, winCodeSize)
	}
}

func TestWinStatesOrder(t *testing.T) {
	// The spill routine compares the state with winStateRunHot to tell a
	// resume from a wait, so both resume states must compare above the rest.
	if winStateIdle >= winStateRunHot || winStateTrapped >= winStateRunHot {
		t.Fatal("a wait state compares at or above a resume state")
	}
	if winStateRunHot+1 != winStateRunCold {
		t.Fatal("the resume states are not adjacent")
	}
}

// chanSignals is a pair of auto-reset events that channels back. A signal
// sets a flag that a wait takes, and a second signal before the wait changes
// nothing, which matches an auto-reset event.
type chanSignals struct {
	guest, host chan struct{}
	// guestSets and hostSets count the signals, to prove that the spin path
	// needed no signal.
	guestSets, hostSets atomic.Int32
}

func newChanSignals() *chanSignals {
	return &chanSignals{guest: make(chan struct{}, 1), host: make(chan struct{}, 1)}
}

func (s *chanSignals) signalHost() error {
	s.hostSets.Add(1)
	select {
	case s.host <- struct{}{}:
	default:
	}
	return nil
}

func (s *chanSignals) waitGuest() error {
	<-s.guest
	return nil
}

func (s *chanSignals) signalGuest() {
	s.guestSets.Add(1)
	select {
	case s.guest <- struct{}{}:
	default:
	}
}

func (s *chanSignals) waitHost() { <-s.host }

// stubPark is the reference model of the wait of the spill routine. It mirrors
// the machine code: publish Trapped, wake a sleeping Sentry, poll, then set the
// flag, test the state again, and sleep. It returns the resume state.
func stubPark(h *winSysmsgHeader, spin int, s *chanSignals) uint32 {
	h.state().Store(winStateTrapped)
	if h.sentryWaiter().Load() != 0 {
		s.signalGuest()
	}
	for range spin {
		if st := h.loadState(); st >= winStateRunHot {
			return st
		}
	}
	for {
		h.stubWaiter().Store(1)
		if st := h.loadState(); st >= winStateRunHot {
			h.stubWaiter().Store(0)
			return st
		}
		s.waitHost()
		h.stubWaiter().Store(0)
		if st := h.loadState(); st >= winStateRunHot {
			return st
		}
	}
}

func TestHandoffRoundTrips(t *testing.T) {
	for _, c := range []struct {
		name               string
		stubSpin, sentSpin int
	}{
		{"sleep on both sides", 0, 0},
		{"spin on both sides", 4096, 4096},
		{"stub sleeps", 0, 4096},
		{"Sentry sleeps", 4096, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			const rounds = 300
			var h winSysmsgHeader
			sig := newChanSignals()
			got := make(chan uint32)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range rounds {
					got <- stubPark(&h, c.stubSpin, sig)
				}
			}()
			sentry := (*sentrySide)(sig)
			for i := range rounds {
				res, err := h.await(winSpin{polls: c.sentSpin}, sentry, func() bool { return false })
				if err != nil || res != winAwaitTrapped {
					t.Fatalf("round %d: await = %v, %v, want trapped", i, res, err)
				}
				want := winStateRunHot
				if i%3 == 0 {
					want = winStateRunCold
				}
				if _, err := h.release(want, sentry); err != nil {
					t.Fatalf("round %d: release: %v", i, err)
				}
				if st := <-got; st != want {
					t.Fatalf("round %d: the stub resumed with state %d, want %d", i, st, want)
				}
			}
			wg.Wait()
		})
	}
}

// sentrySide gives the Sentry view of chanSignals.
type sentrySide chanSignals

func (s *sentrySide) signalHost() error { return (*chanSignals)(s).signalHost() }
func (s *sentrySide) waitGuest() error  { return (*chanSignals)(s).waitGuest() }

func TestHandoffSpinHitNeedsNoSignal(t *testing.T) {
	var h winSysmsgHeader
	sig := newChanSignals()
	sentry := (*sentrySide)(sig)
	h.state().Store(winStateTrapped)
	if res, err := h.await(winSpin{polls: testSpinPolls}, sentry, func() bool { return false }); err != nil || res != winAwaitTrapped {
		t.Fatalf("await = %v, %v", res, err)
	}
	h.stubWaiter().Store(0)
	woke, err := h.release(winStateRunHot, sentry)
	if err != nil || woke {
		t.Fatalf("release woke a stub that does not sleep: woke %v, err %v", woke, err)
	}
	if n := sig.hostSets.Load(); n != 0 {
		t.Fatalf("the hot path set the host event %d times", n)
	}
}

func TestHandoffReleaseWakesSleepingStub(t *testing.T) {
	var h winSysmsgHeader
	sig := newChanSignals()
	sentry := (*sentrySide)(sig)
	h.state().Store(winStateTrapped)
	h.stubWaiter().Store(1)
	woke, err := h.release(winStateRunCold, sentry)
	if err != nil || !woke {
		t.Fatalf("release did not wake a sleeping stub: woke %v, err %v", woke, err)
	}
	select {
	case <-sig.host:
	default:
		t.Fatal("release did not set the host event")
	}
	if got := h.loadState(); got != winStateRunCold {
		t.Fatalf("state after release = %d, want %d", got, winStateRunCold)
	}
}

func TestHandoffAwaitReturnsOnPendingReason(t *testing.T) {
	for _, spin := range []int{0, testSpinPolls} {
		var h winSysmsgHeader
		sig := newChanSignals()
		sentry := (*sentrySide)(sig)
		h.state().Store(winStateIdle)
		res, err := h.await(winSpin{polls: spin}, sentry, func() bool { return true })
		if err != nil || res != winAwaitPending {
			t.Fatalf("spin %d: await = %v, %v, want pending", spin, res, err)
		}
		if h.sentryWaiter().Load() != 0 {
			t.Fatalf("spin %d: await returned with the waiter flag set", spin)
		}
	}
}

func TestHandoffAwaitWakesOnPendingSignal(t *testing.T) {
	var h winSysmsgHeader
	sig := newChanSignals()
	sentry := (*sentrySide)(sig)
	var pend atomic.Bool
	done := make(chan winAwait)
	go func() {
		res, _ := h.await(winSpin{}, sentry, pend.Load)
		done <- res
	}()
	// A source of a pending reason sets the condition after the Sentry sleeps,
	// then wakes the sleeper when it reads a non-zero flag.
	for h.sentryWaiter().Load() == 0 {
		runtime.Gosched()
	}
	pend.Store(true)
	if h.sentryWaiter().Load() != 0 {
		sig.signalGuest()
	}
	if res := <-done; res != winAwaitPending {
		t.Fatalf("await = %v, want pending", res)
	}
}

func TestHandoffAwaitIgnoresStaleSignal(t *testing.T) {
	var h winSysmsgHeader
	sig := newChanSignals()
	sentry := (*sentrySide)(sig)
	// A signal from an earlier round is still set. The state is not Trapped,
	// so await must sleep again until the stub publishes the state.
	sig.signalGuest()
	done := make(chan winAwait)
	go func() {
		res, _ := h.await(winSpin{}, sentry, func() bool { return false })
		done <- res
	}()
	for h.loadState() == winStateTrapped || h.sentryWaiter().Load() == 0 || len(sig.guest) != 0 {
		runtime.Gosched()
	}
	h.state().Store(winStateTrapped)
	sig.signalGuest()
	if res := <-done; res != winAwaitTrapped {
		t.Fatalf("await = %v, want trapped", res)
	}
}

type failingSignals struct{ err error }

func (f failingSignals) signalHost() error { return f.err }
func (f failingSignals) waitGuest() error  { return f.err }

func TestHandoffPropagatesWaitFailure(t *testing.T) {
	var h winSysmsgHeader
	boom := errors.New("the stub died")
	if _, err := h.await(winSpin{}, failingSignals{boom}, func() bool { return false }); !errors.Is(err, boom) {
		t.Fatalf("await error = %v, want %v", err, boom)
	}
	if h.sentryWaiter().Load() != 0 {
		t.Fatal("await returned with the waiter flag set")
	}
	h.stubWaiter().Store(1)
	if _, err := h.release(winStateRunHot, failingSignals{boom}); !errors.Is(err, boom) {
		t.Fatalf("release error = %v, want %v", err, boom)
	}
}
