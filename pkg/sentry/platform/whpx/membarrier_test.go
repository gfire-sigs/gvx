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
	"sync"
	"testing"
)

func TestPlatformReportsGlobalMemoryBarrier(t *testing.T) {
	p := newTestPlatform(t, newFakeBackend(), Options{})
	if !p.HaveGlobalMemoryBarrier() {
		t.Fatal("HaveGlobalMemoryBarrier() = false, want true")
	}
}

func TestGlobalMemoryBarrierWaitsForRunningProcessors(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	a, leaveA := activeVP(t, p, fb, as)
	b, leaveB := activeVP(t, p, fb, as)

	done := make(chan error, 1)
	go func() { done <- p.GlobalMemoryBarrier() }()
	waitCancels(fb, a, 1)
	waitCancels(fb, b, 1)
	select {
	case err := <-done:
		t.Fatalf("GlobalMemoryBarrier returned %v while two processors ran guest code", err)
	default:
	}
	leaveA()
	select {
	case err := <-done:
		t.Fatalf("GlobalMemoryBarrier returned %v while one processor still ran guest code", err)
	default:
	}
	leaveB()
	if err := <-done; err != nil {
		t.Fatalf("GlobalMemoryBarrier = %v", err)
	}
}

func TestGlobalMemoryBarrierLeavesIdleProcessorsAlone(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	if err := p.GlobalMemoryBarrier(); err != nil {
		t.Fatalf("GlobalMemoryBarrier without processors = %v", err)
	}
	as := newTestAS(t, p)
	v, leave := activeVP(t, p, fb, as)
	leave()
	if err := p.GlobalMemoryBarrier(); err != nil {
		t.Fatalf("GlobalMemoryBarrier with an idle processor = %v", err)
	}
	fb.mu.Lock()
	cancels := fb.vps[v.index].cancels
	fb.mu.Unlock()
	if cancels != 0 {
		t.Fatalf("the idle processor received %d cancels, want 0", cancels)
	}
}

func TestGlobalMemoryBarrierCallsRunConcurrently(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	v, leave := activeVP(t, p, fb, as)

	const callers = 4
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- p.GlobalMemoryBarrier()
		}()
	}
	waitCancels(fb, v, 1)
	leave()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("GlobalMemoryBarrier = %v", err)
		}
	}
}
