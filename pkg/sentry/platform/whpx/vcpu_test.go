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
	"testing"
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
	for {
		p.mu.Lock()
		n := p.waiters
		p.mu.Unlock()
		if n > 0 {
			break
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
