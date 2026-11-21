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

package whpx

import (
	"errors"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// limitVPs shrinks the processor pool of a fresh platform to n processors.
func limitVPs(p *Platform, n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.vpCount = n
	p.freeIdx = p.freeIdx[len(p.freeIdx)-n:]
}

func TestAcquireCreatesProcessorsLazilyUpToTheLimit(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	limitVPs(p, 2)
	if len(fb.vps) != 0 {
		t.Fatalf("%d processors exist before the first Switch", len(fb.vps))
	}
	a, err := p.acquire(newContext(p))
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.acquire(newContext(p))
	if err != nil {
		t.Fatal(err)
	}
	if a.index == b.index || len(fb.vps) != 2 {
		t.Fatalf("processors %d and %d, %d created", a.index, b.index, len(fb.vps))
	}

	// With both processors busy, a third acquire blocks until a release.
	got := make(chan *vcpu)
	go func() {
		v, err := p.acquire(newContext(p))
		if err != nil {
			t.Error(err)
		}
		got <- v
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p.mu.Lock()
		n := p.waiters
		p.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("third acquire did not queue a waiter within 10s")
		}
		runtime.Gosched()
	}
	select {
	case v := <-got:
		t.Fatalf("acquire returned processor %d while all were busy", v.index)
	default:
	}
	p.release(a)
	v := <-got
	if v != a {
		t.Errorf("waiter got processor %d, want the released processor %d", v.index, a.index)
	}
	if len(fb.vps) != 2 {
		t.Errorf("%d processors exist, limit is 2", len(fb.vps))
	}
	p.release(v)
	p.release(b)
}

func TestAcquirePrefersTheLastProcessor(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	limitVPs(p, 3)
	c := newContext(p)
	first, _ := p.acquire(c)
	c.lastVP = first
	other, _ := p.acquire(newContext(p))
	p.release(other)
	p.release(first)
	again, err := p.acquire(c)
	if err != nil || again != first {
		t.Errorf("acquire returned %v, %v, want the last processor %d", again, err, first.index)
	}
	p.release(again)
}

func TestFailedProcessorCreationReturnsTheIndex(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	limitVPs(p, 1)
	boom := errors.New("create vp boom")
	fb.vpErr = func(uint32) error { return boom }
	if _, err := p.acquire(newContext(p)); !errors.Is(err, boom) {
		t.Fatalf("acquire returned %v", err)
	}
	fb.vpErr = nil
	v, err := p.acquire(newContext(p))
	if err != nil || v == nil {
		t.Fatalf("the index was lost after a failed creation: %v", err)
	}
	if len(fb.vps) != 1 {
		t.Errorf("%d processors exist", len(fb.vps))
	}
	p.release(v)
}

func TestFailedBringUpDeletesTheProcessor(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	limitVPs(p, 1)
	boom := errors.New("set registers boom")
	fb.setErr = func(uint32) error { return boom }
	if _, err := p.acquire(newContext(p)); !errors.Is(err, boom) {
		t.Fatalf("acquire returned %v", err)
	}
	if len(fb.vps) != 0 {
		t.Errorf("a processor that failed bring-up stays in the partition")
	}
}

func TestCloseCancelsRunningProcessorsAndWaits(t *testing.T) {
	fb := newFakeBackend()
	p, err := newPlatform(fb, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	as := newTestAS(t, p)
	v, leave := activeVP(t, p, fb, as)
	closed := make(chan error)
	go func() { closed <- p.Close() }()
	waitCancels(fb, v, 1)
	select {
	case <-closed:
		t.Fatal("Close returned while a processor ran guest code")
	default:
	}
	leave()
	if err := <-closed; err != nil {
		t.Errorf("Close returned %v", err)
	}
	if len(fb.vps) != 0 {
		t.Error("a processor survives Close")
	}
}

func TestKickAndWaitReSendsALostCancel(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	v, leave := activeVP(t, p, fb, as)
	done := make(chan struct{})
	go func() {
		v.kickAndWait()
		close(done)
	}()
	// The first cancel brings no reaction, as if it arrived too early. The
	// timer sends a second one.
	waitCancels(fb, v, 2)
	leave()
	<-done
}

func TestAcquireSerializesProcessorCreationInOrder(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{processors: 4})

	const workers = 4
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	unblockFirst := func() { releaseOnce.Do(func() { close(releaseFirst) }) }

	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	var orderMu sync.Mutex
	var order []uint32

	fb.onCreateVP = func(index uint32) {
		cur := inFlight.Add(1)
		for {
			prev := maxInFlight.Load()
			if cur <= prev || maxInFlight.CompareAndSwap(prev, cur) {
				break
			}
		}
		defer inFlight.Add(-1)

		orderMu.Lock()
		order = append(order, index)
		first := len(order) == 1
		orderMu.Unlock()

		if first {
			close(firstEntered)
			<-releaseFirst
		}
	}

	got := make([]*vcpu, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	defer func() {
		unblockFirst()
		wg.Wait()
		for i, v := range got {
			if v != nil {
				p.release(v)
				got[i] = nil
			}
		}
	}()

	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = p.acquire(newContext(p))
		}(i)
	}

	<-firstEntered
	deadline := time.Now().Add(10 * time.Second)
	for {
		p.mu.Lock()
		w := p.waiters
		p.mu.Unlock()
		if w == workers-1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d waiters during in-flight createVP, got %d", workers-1, w)
		}
		runtime.Gosched()
	}
	unblockFirst()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("acquire[%d] returned %v", i, err)
		}
	}
	if peak := maxInFlight.Load(); peak != 1 {
		t.Fatalf("max concurrent createVP calls = %d, want 1", peak)
	}
	wantOrder := []uint32{0, 1, 2, 3}
	if !slices.Equal(order, wantOrder) {
		t.Fatalf("createVP index order = %v, want %v", order, wantOrder)
	}
}

func TestCloseWaitsForInFlightProcessorCreation(t *testing.T) {
	fb := newFakeBackend()
	p, err := newPlatform(fb, testOptions())
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	fb.onCreateVP = func(uint32) {
		close(entered)
		<-release
	}

	acqErr := make(chan error, 1)
	go func() {
		v, err := p.acquire(newContext(p))
		if v != nil {
			p.release(v)
		}
		acqErr <- err
	}()
	<-entered

	closeErr := make(chan error, 1)
	go func() {
		closeErr <- p.Close()
	}()
	acqDone, closeDone := false, false
	defer func() {
		unblock()
		if !acqDone {
			<-acqErr
		}
		if !closeDone {
			<-closeErr
		}
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not mark platform closed within 10s")
		}
		runtime.Gosched()
	}
	select {
	case err := <-closeErr:
		closeDone = true
		t.Fatalf("Close returned %v while createVP was still in flight", err)
	default:
	}

	unblock()
	acqDone = true
	if err := <-acqErr; !errors.Is(err, errClosed) {
		t.Fatalf("acquire returned %v, want %v", err, errClosed)
	}
	closeDone = true
	if err := <-closeErr; err != nil {
		t.Fatalf("Close returned %v", err)
	}
	fb.mu.Lock()
	remaining := len(fb.vps)
	open := fb.partitionOpen
	fb.mu.Unlock()
	if remaining != 0 || open {
		t.Fatalf("after Close: %d processors remain, partitionOpen=%v", remaining, open)
	}
}

func TestAcquireWaiterRetriesIndexAfterFailedCreation(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{processors: 2})

	boom := errors.New("transient createVP failure")
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	unblockFirst := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	var calls atomic.Int32

	fb.onCreateVP = func(uint32) {
		if calls.Add(1) == 1 {
			close(firstEntered)
			<-releaseFirst
		}
	}
	fb.vpErr = func(uint32) error {
		if calls.Load() == 1 {
			return boom
		}
		return nil
	}

	type result struct {
		v   *vcpu
		err error
	}
	firstRes := make(chan result, 1)
	secondRes := make(chan result, 1)
	firstDone, secondDone := false, false
	defer func() {
		unblockFirst()
		if !firstDone {
			if r := <-firstRes; r.v != nil {
				p.release(r.v)
			}
		}
		if !secondDone {
			if r := <-secondRes; r.v != nil {
				p.release(r.v)
			}
		}
	}()

	go func() {
		v, err := p.acquire(newContext(p))
		firstRes <- result{v: v, err: err}
	}()
	<-firstEntered

	go func() {
		v, err := p.acquire(newContext(p))
		secondRes <- result{v: v, err: err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p.mu.Lock()
		w := p.waiters
		p.mu.Unlock()
		if w == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 1 waiter during failed createVP, got %d", w)
		}
		runtime.Gosched()
	}

	unblockFirst()
	firstDone = true
	r1 := <-firstRes
	if r1.v != nil {
		p.release(r1.v)
	}
	if !errors.Is(r1.err, boom) {
		t.Fatalf("first acquire = (%v, %v), want %v", r1.v, r1.err, boom)
	}
	secondDone = true
	r2 := <-secondRes
	if r2.v != nil {
		defer p.release(r2.v)
	}
	if r2.err != nil || r2.v == nil {
		t.Fatalf("second acquire = (%v, %v), want valid vcpu", r2.v, r2.err)
	}
	if r2.v.index != 0 {
		t.Fatalf("retried processor index = %d, want 0", r2.v.index)
	}
}
