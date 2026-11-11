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

package kernel

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/waiter"
)

func roundTripState[T any](t *testing.T, loadCtx context.Context, src T) T {
	t.Helper()
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, &src); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	var dst T
	if _, err := state.Load(loadCtx, &buf, &dst); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	return dst
}

func TestKernelLogSaveLoadRoundTrip(t *testing.T) {
	kOrig := &Kernel{}
	if !kOrig.SetKernelLogBufLen(KernelLogMinBufLen * 2) {
		t.Fatal("SetKernelLogBufLen returned false")
	}
	orig := kOrig.KernelLog()
	orig.SetDmesgRestrict(true)
	orig.SetDevkmsgMode(DevkmsgOn)
	if !orig.SetConsoleLevel(5) {
		t.Fatal("SetConsoleLevel(5) returned false")
	}
	orig.ConsoleOff()

	orig.Printk(LogInfo, "boot-one")
	orig.Printk(LogWarning, "boot-two")
	orig.Printk(LogErr, "boot-three")
	orig.Clear()
	orig.Printk(LogNotice, "post-clear")

	// Consume 6 bytes of the first unread syslog line so syslogPartial is non-zero.
	partial := orig.Read(6)
	if len(partial) != 6 {
		t.Fatalf("Read(6) = %d bytes, want 6", len(partial))
	}

	kRestored := &Kernel{}
	loadCtx := context.WithValue(context.Background(), CtxKernel, kRestored)
	loaded := roundTripState(t, loadCtx, orig)

	if got := kRestored.LookupKernelLog(); got != loaded {
		t.Fatalf("LookupKernelLog = %p, want %p", got, loaded)
	}
	if got := kRestored.KernelLog(); got != loaded {
		t.Fatalf("KernelLog = %p, want %p", got, loaded)
	}
	if got, want := loaded.BufLen(), KernelLogMinBufLen*2; got != want {
		t.Errorf("BufLen = %d, want %d", got, want)
	}
	if !loaded.DmesgRestrict() {
		t.Error("DmesgRestrict = false, want true")
	}
	if got := loaded.DevkmsgMode(); got != DevkmsgOn {
		t.Errorf("DevkmsgMode = %v, want %v", got, DevkmsgOn)
	}
	if got := loaded.Levels()[0]; got != minimumConsoleLogLevel {
		t.Errorf("console level while disabled = %d, want %d", got, minimumConsoleLogLevel)
	}
	loaded.ConsoleOn()
	if got := loaded.Levels()[0]; got != 5 {
		t.Errorf("restored console level = %d, want 5", got)
	}

	if got, want := loaded.FirstSeq(), uint64(0); got != want {
		t.Errorf("FirstSeq = %d, want %d", got, want)
	}
	if got, want := loaded.NextSeq(), uint64(4); got != want {
		t.Errorf("NextSeq = %d, want %d", got, want)
	}
	rec, ok := loaded.Lookup(2)
	if !ok || rec.Text != "boot-three" || rec.Level != LogErr {
		t.Errorf("Lookup(2) = (%+v, %t), want boot-three at LogErr", rec, ok)
	}

	// ReadAll respects clearSeq and returns only records after Clear().
	afterClear := string(loaded.ReadAll(4096, false))
	if strings.Contains(afterClear, "boot-one") || !strings.Contains(afterClear, "post-clear") {
		t.Errorf("ReadAll after Clear = %q, want post-clear only", afterClear)
	}

	// Read resumes from the saved syslogSeq and syslogPartial offset.
	rest := loaded.Read(4096)
	joined := string(partial) + string(rest)
	for _, want := range []string{"boot-one", "boot-two", "boot-three", "post-clear"} {
		if !strings.Contains(joined, want) {
			t.Errorf("joined syslog stream %q lacks %q", joined, want)
		}
	}

	// Verify waiter queue notifications work on the restored KernelLog.
	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := loaded.EventRegister(&e); err != nil {
		t.Fatalf("EventRegister: %v", err)
	}
	defer loaded.EventUnregister(&e)
	loaded.Printk(LogInfo, "after-restore")
	select {
	case <-ch:
	default:
		t.Error("Printk on restored KernelLog did not notify registered waiter")
	}
}

func TestLogRateLimitSaveLoadRoundTrip(t *testing.T) {
	var orig LogRateLimit
	base := 10 * time.Second
	for i := range 12 {
		allowed := orig.Allow(base + time.Duration(i)*time.Millisecond)
		if want := i < logRateBurst; allowed != want {
			t.Fatalf("Allow(%d) = %t, want %t", i, allowed, want)
		}
	}

	loaded := roundTripState(t, context.Background(), &orig)
	if loaded.Allow(base + time.Second) {
		t.Error("Allow inside the saved window succeeded after burst was spent")
	}
	if got := loaded.Missed(); got != 3 {
		t.Errorf("Missed = %d, want 3", got)
	}
	// Advancing past logRateInterval opens a fresh burst window while retaining missed count.
	if !loaded.Allow(base + logRateInterval + time.Second) {
		t.Error("Allow after logRateInterval failed on restored LogRateLimit")
	}
	if got := loaded.Missed(); got != 3 {
		t.Errorf("Missed after new window = %d, want 3", got)
	}
}

func TestCPUBandwidthSaveLoadRoundTrip(t *testing.T) {
	clock := fakeBandwidthClock{now: 1000 * ms}
	parent := newTestBandwidth(t, &clock, nil, 80*time.Millisecond)
	child := newTestBandwidth(t, &clock, parent, 50*time.Millisecond)

	ran(&clock, child, 62*ms)
	if !child.Throttled() {
		t.Fatal("child is not throttled before save")
	}
	// Finish one throttled period so nrThrottled == 1, then throttle again before save.
	clock.advance(period)
	ran(&clock, child, 62*ms)
	if !child.Throttled() {
		t.Fatal("child is not throttled in second period before save")
	}

	pair := [2]*CPUBandwidth{parent, child}
	var saveBuf bytes.Buffer
	if _, err := state.Save(context.Background(), &saveBuf, &pair); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	savedBytes := saveBuf.Bytes()

	// Loading without ActivateRestored must not increment global counters or leak timers.
	baseLim := cpuBandwidthLimited.Load()
	baseThr := cpuBandwidthThrottled.Load()
	var unactivated [2]*CPUBandwidth
	if _, err := state.Load(context.Background(), bytes.NewReader(savedBytes), &unactivated); err != nil {
		t.Fatalf("state.Load(unactivated): %v", err)
	}
	if got := cpuBandwidthLimited.Load(); got != baseLim {
		t.Fatalf("cpuBandwidthLimited after state.Load = %d, want %d before ActivateRestored", got, baseLim)
	}
	if got := cpuBandwidthThrottled.Load(); got != baseThr {
		t.Fatalf("cpuBandwidthThrottled after state.Load = %d, want %d before ActivateRestored", got, baseThr)
	}
	// Releasing unactivated nodes must keep global counters unchanged.
	unactivated[1].SetLimits(-1, period)
	unactivated[0].SetLimits(-1, period)
	if got := cpuBandwidthLimited.Load(); got != baseLim {
		t.Fatalf("cpuBandwidthLimited after unactivated release = %d, want %d", got, baseLim)
	}
	if got := cpuBandwidthThrottled.Load(); got != baseThr {
		t.Fatalf("cpuBandwidthThrottled after unactivated release = %d, want %d", got, baseThr)
	}

	var loaded [2]*CPUBandwidth
	if _, err := state.Load(context.Background(), bytes.NewReader(savedBytes), &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	loadedParent, loadedChild := loaded[0], loaded[1]
	t.Cleanup(func() {
		loadedChild.SetLimits(-1, period)
		loadedParent.SetLimits(-1, period)
	})
	now := BandwidthNow()
	loadedParent.ActivateRestored(now)
	loadedChild.ActivateRestored(now)
	if got, want := cpuBandwidthLimited.Load(), baseLim+2; got != want {
		t.Errorf("cpuBandwidthLimited after ActivateRestored = %d, want %d", got, want)
	}
	if got, want := cpuBandwidthThrottled.Load(), baseThr+1; got != want {
		t.Errorf("cpuBandwidthThrottled after ActivateRestored = %d, want %d", got, want)
	}

	if loadedChild.Parent() != loadedParent {
		t.Fatalf("loadedChild.Parent() = %p, want %p", loadedChild.Parent(), loadedParent)
	}
	if q, p, ok := loadedParent.Limit(); !ok || q != 80*time.Millisecond || p != period {
		t.Errorf("loadedParent.Limit() = (%v, %v, %t), want (80ms, 100ms, true)", q, p, ok)
	}
	if q, p, ok := loadedChild.Limit(); !ok || q != 50*time.Millisecond || p != period {
		t.Errorf("loadedChild.Limit() = (%v, %v, %t), want (50ms, 100ms, true)", q, p, ok)
	}
	if !loadedChild.Throttled() {
		t.Error("loadedChild.Throttled() = false, want true")
	}

	// Raise quota to unthrottle and verify throttled period accounting survives.
	loadedChild.SetLimits(200*time.Millisecond, period)
	if loadedChild.Throttled() {
		t.Error("loadedChild remained throttled after quota increase")
	}
	if got := loadedChild.Stats().Throttled; got != 1 {
		t.Errorf("Stats().Throttled = %d, want 1", got)
	}
}

func TestKernelLogBufLenAndTaskCPUMetersHelpers(t *testing.T) {
	k := &Kernel{}
	if got := k.KernelLogBufLen(); got != 0 {
		t.Fatalf("initial KernelLogBufLen = %d, want 0", got)
	}
	wantLen := KernelLogMinBufLen * 4
	if !k.SetKernelLogBufLen(wantLen) {
		t.Fatal("SetKernelLogBufLen returned false")
	}
	if got := k.KernelLogBufLen(); got != wantLen {
		t.Fatalf("pre-allocation KernelLogBufLen = %d, want %d", got, wantLen)
	}
	if got := k.KernelLog().BufLen(); got != wantLen {
		t.Fatalf("allocated KernelLog.BufLen = %d, want %d", got, wantLen)
	}

	k.tasks = newTaskSet(NewRootPIDNamespace(auth.NewRootUserNamespace()))
	t1 := &Task{k: k}
	t2 := &Task{k: k}
	k.tasks.mu.Lock()
	k.tasks.Root.tids[t1] = 1
	k.tasks.Root.tids[t2] = 2
	k.tasks.mu.Unlock()

	t1.SetCPUTimeMeasured(42 * time.Millisecond)
	meters := k.SaveTaskCPUMeters()
	if got, want := meters[t1], (42 * time.Millisecond).Nanoseconds(); got != want {
		t.Fatalf("SaveTaskCPUMeters()[t1] = %d, want %d", got, want)
	}
	if _, exists := meters[t2]; exists {
		t.Fatal("SaveTaskCPUMeters() recorded zero-usage task t2")
	}

	t1.SetCPUTimeMeasured(0)
	k.LoadTaskCPUMeters(meters)
	if got, want := t1.CPUTimeMeasured(), 42*time.Millisecond; got != want {
		t.Fatalf("t1.CPUTimeMeasured() after LoadTaskCPUMeters = %v, want %v", got, want)
	}
}

func TestCPUMeterSaveLoadRoundTrip(t *testing.T) {
	var orig cpuMeter
	orig.start(100)
	orig.stop(450)
	if got := orig.measured(450, false); got != 350 {
		t.Fatalf("orig.measured = %d, want 350", got)
	}

	loaded := roundTripState(t, context.Background(), &orig)
	if got := loaded.measured(450, false); got != 350 {
		t.Errorf("loaded.measured = %d, want 350", got)
	}
	loaded.start(1000)
	loaded.stop(1200)
	if got := loaded.measured(1200, false); got != 550 {
		t.Errorf("loaded.measured after run = %d, want 550", got)
	}
}
