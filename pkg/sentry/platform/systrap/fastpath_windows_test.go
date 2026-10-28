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

//go:build windows

package systrap

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	sentrytime "z.gfire.dev/gvx/pkg/sentry/time"
)

// These tests require the fast path, whatever GVX_SYSTRAP_FASTPATH says. The
// rest of the engine tests run with the fast path by default.

// newFastPlatform returns a platform that runs system calls through the fast
// path. New runs the self test and fails when the host cannot run it.
func newFastPlatform(t testing.TB) *Platform {
	t.Helper()
	prev := fastPathMode
	fastPathMode = fastPathRequired
	t.Cleanup(func() { fastPathMode = prev })
	p := newPlatform(t)
	if !p.fast {
		t.Fatal("the platform does not run the fast path")
	}
	return p
}

// fastStats returns the counters of the fast path of the thread of r.
func fastStats(t testing.TB, r *rig) *fastThread {
	t.Helper()
	th := r.ctx.th.Load()
	if th == nil {
		t.Fatal("the context has no thread")
	}
	f := th.fast.Load()
	if f == nil {
		t.Fatal("the thread has no fast slot")
	}
	return f
}

func TestFastPathServesEverySystemCall(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	var prog []byte
	const n = 150
	for i := 0; i < n; i++ {
		prog = append(prog, gSyscall(uint64(100+i%50), uint64(i))...)
	}
	if len(prog) > blockSize {
		t.Fatalf("program of %d bytes does not fit one page", len(prog))
	}
	r.program(prog)
	for i := 0; i < n; i++ {
		si, _, err := r.run()
		mustSyscall(t, si, err, uint64(100+i%50), r.ac)
		if got := regArg(r.ac, 0); got != uint64(i) {
			t.Fatalf("call %d: argument = %d", i, got)
		}
		setRet(r.ac, uint64(i))
	}
	if got := fastStats(t, r).traps.Load(); got != n {
		t.Errorf("the fast path served %d of %d system calls", got, n)
	}
}

func TestFastPathChangedProgramCounterTakesColdResume(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	mem := r.program(gSyscall(1))
	// The second call sits at an address that the first call does not reach.
	copy(mem[0x100:], gSyscall(7))
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	// A signal handler or a sigreturn changes the program counter at a call.
	r.ac.SetIP(codeVA + 0x100)
	si, _, err = r.run()
	mustSyscall(t, si, err, 7, r.ac)
	f := fastStats(t, r)
	if got := f.colds.Load(); got != 1 {
		t.Errorf("cold resumes = %d, want 1", got)
	}
	if got := f.traps.Load(); got != 2 {
		t.Errorf("fast traps = %d, want 2", got)
	}
}

func TestFastPathInterruptStopsGuestAfterSystemCall(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	r.program(gSyscall(1), gCountSpin())
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	type result struct {
		si  *linux.SignalInfo
		err error
	}
	done := make(chan result, 1)
	go func() {
		si, _, err := r.run()
		done <- result{si, err}
	}()
	time.Sleep(200 * time.Millisecond)
	r.ctx.Interrupt()
	select {
	case res := <-done:
		if !errors.Is(res.err, platform.ErrContextInterrupt) || res.si != nil {
			t.Fatalf("Switch = (%s, %v), want an interrupt", describe(res.si), res.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an interrupt did not stop a guest that spins after a fast system call")
	}
	if regAcc(r.ac) == 0 {
		t.Error("the guest counted nothing before the interrupt")
	}
}

func TestFastPathInterruptBeforeSwitchKeepsTheTrap(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	r.program(gSyscall(3), gSyscall(4))
	si, _, err := r.run()
	mustSyscall(t, si, err, 3, r.ac)
	// The thread waits in the spill routine. An interrupt returns at once and
	// leaves it there, and the next Switch resumes it.
	r.ctx.Interrupt()
	si, _, err = r.run()
	if si != nil || !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch = (%s, %v), want ErrContextInterrupt", describe(si), err)
	}
	si, _, err = r.run()
	mustSyscall(t, si, err, 4, r.ac)
}

func TestFastPathVectorStateFollowsTheSentry(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	r.program(gSetVector(0x1111), gSyscall(1), gVectorToReg(), gSyscall(2))
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	if err := r.ctx.PullFullState(r.as, r.ac); err != nil {
		t.Fatalf("PullFullState: %v", err)
	}
	if got := vectorLow(r.ac); got != 0x1111 {
		t.Errorf("the Sentry read vector low %#x, want 0x1111", got)
	}
	setVectorLow(r.ac, 0x2222)
	r.ctx.FullStateChanged()
	si, _, err = r.run()
	mustSyscall(t, si, err, 2, r.ac)
	if got := regAcc(r.ac); got != 0x2222 {
		t.Errorf("the guest read vector low %#x, want 0x2222 from the Sentry", got)
	}
}

func TestFastPathSlotsAreReused(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	r.program(gSyscall(5))
	const rounds = 20
	for i := 0; i < rounds; i++ {
		th := r.newThread()
		th.ac.SetIP(codeVA)
		th.ac.SetStack(stackVA + blockSize/2)
		si, _, err := th.run()
		mustSyscall(t, si, err, 5, th.ac)
		th.ctx.Release()
	}
	r.as.sp.fast.mu.Lock()
	created := len(r.as.sp.fast.all)
	r.as.sp.fast.mu.Unlock()
	if created > 2 {
		t.Errorf("the stub created %d fast slots for %d threads that ran one after another", created, rounds)
	}
}

func TestFastPathConcurrentThreads(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	var prog []byte
	const calls = 60
	for i := 0; i < calls; i++ {
		prog = append(prog, gSyscall(uint64(200+i), uint64(i))...)
	}
	r.program(prog)
	const threads = 4
	var wg sync.WaitGroup
	errs := make(chan string, threads)
	for k := 0; k < threads; k++ {
		th := r.newThread()
		th.ac.SetIP(codeVA)
		th.ac.SetStack(uintptr(stackVA + 0x800 + uint64(k)*0x100))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < calls; i++ {
				si, _, err := th.run()
				if si != nil || err != nil {
					errs <- "Switch returned a signal or an error"
					return
				}
				if regNr(th.ac) != uint64(200+i) || regArg(th.ac, 0) != uint64(i) {
					errs <- "a thread saw the registers of another thread or a lost register"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

func TestFastPathProbeRoundTrip(t *testing.T) {
	prev := fastPathMode
	fastPathMode = fastPathRequired
	t.Cleanup(func() { fastPathMode = prev })
	info, err := Probe()
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	t.Logf("fast path round trip %v", info.RoundTrip)
}

func TestParseFastPathMode(t *testing.T) {
	for in, want := range map[string]fastPathSetting{
		"":      fastPathAuto,
		"1":     fastPathRequired,
		"0":     fastPathOff,
		"true":  fastPathAuto,
		"other": fastPathAuto,
	} {
		if got := parseFastPathMode(in); got != want {
			t.Errorf("parseFastPathMode(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestAutoModeUsesTheFastPath checks that the default platform runs the fast
// path on a host that can run it. The other tests of the engine then cover the
// fast path without a special setting.
func TestAutoModeUsesTheFastPath(t *testing.T) {
	prev := fastPathMode
	fastPathMode = fastPathAuto
	t.Cleanup(func() { fastPathMode = prev })
	p := newPlatform(t)
	if !p.fast {
		t.Skip("this host cannot run the fast path, so New fell back to the debug path")
	}
}

// TestOffModeUsesTheDebugPath checks that GVX_SYSTRAP_FASTPATH=0 keeps the
// debug path.
func TestOffModeUsesTheDebugPath(t *testing.T) {
	prev := fastPathMode
	fastPathMode = fastPathOff
	t.Cleanup(func() { fastPathMode = prev })
	if p := newPlatform(t); p.fast {
		t.Fatal("the platform runs the fast path with the mode off")
	}
}

func TestFastPathIslandSlotsReclaimedOnRepatchAndUnmap(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	r.program(gJump(dataVA))
	var blockProg []byte
	for i := 0; i < 16; i++ {
		blockProg = append(blockProg, gSyscall(11)...)
	}
	r.mapPage(dataVA, hostarch.AccessType{Read: true, Write: true, Execute: true}, blockProg)
	si, _, err := r.run()
	mustSyscall(t, si, err, 11, r.ac)

	// Each patch of dataVA allocates 16 slots (1024 bytes on amd64, 768 bytes
	// on arm64). Eight repatches exceed one 4KB island unless restoreData
	// reclaims the block's slots.
	const rounds = 8
	for i := 0; i < rounds; i++ {
		if ok, err := r.as.restoreData(dataVA); !ok || err != nil {
			t.Fatalf("round %d: restoreData = (%v, %v), want (true, nil)", i, ok, err)
		}
		r.ac.SetIP(dataVA)
		si, _, err := r.run()
		mustSyscall(t, si, err, 11, r.ac)
	}
	if got := fastStats(t, r).traps.Load(); got != rounds+1 {
		t.Fatalf("fast traps = %d, want %d", got, rounds+1)
	}

	r.as.mu.Lock()
	islandCount := len(r.as.islands)
	r.as.mu.Unlock()
	if islandCount != 1 {
		t.Fatalf("islands allocated after %d repatches = %d, want 1", rounds, islandCount)
	}

	r.as.Unmap(hostarch.Addr(dataVA), blockSize)
	r.as.mu.Lock()
	defer r.as.mu.Unlock()
	for base, isl := range r.as.islands {
		for wIdx, bits := range isl.usedBits {
			if bits != 0 {
				t.Errorf("island %#x word %d has usedBits %#x after Unmap, want 0", base, wIdx, bits)
			}
		}
	}
}

// sleepRoundTripDelay is how long the Sentry holds a trapped thread in the
// sleep case of BenchmarkFastPathRoundTrip. It exceeds the spin of the stub by
// a wide margin, so the stub sleeps on the host event before the resume.
const sleepRoundTripDelay = time.Millisecond

// BenchmarkFastPathRoundTrip measures one round trip of the fast path: the
// guest traps, the Sentry sees the trap, answers with a fixed result and no
// other work, and the guest resumes and traps again. The guest is a loop of
// one patched system call.
//
// The spin case resumes the thread at once, so the stub finds the resume state
// while it spins. The sleep case holds the thread for sleepRoundTripDelay
// first, so the stub sleeps on the host event and the resume wakes it. The
// metric ns/roundtrip counts only the time in Switch, which the performance
// counter measures. It includes two counter reads, about 20 to 60 ns. ns/op
// also counts the delay of the sleep case.
//
// The always variants run the spill routine that loads the vector state on every
// hot resume, so they give the cost before the call flag and FPDirty. The
// novector variants run a spill routine without the save and the restore of the
// vector state. They give the upper bound of what skipping the vector state can
// save. The routine breaks a guest that uses a vector register, so only this
// benchmark runs it. The live variants run a guest that holds a live
// vector state, so a restore of that state reads memory. The other guests leave
// the vector state in its initial configuration, which a restore loads without
// a read.
//
// Run it through the diagnose workflow with a script, for example:
// go test -run '^$' -bench BenchmarkFastPathRoundTrip -count 5 ./pkg/sentry/platform/systrap/
func BenchmarkFastPathRoundTrip(b *testing.B) {
	for _, c := range []struct {
		name  string
		opts  spillOptions
		live  bool
		delay time.Duration
	}{
		{"vector/spin", spillOptions{}, false, 0},
		{"vector/sleep", spillOptions{}, false, sleepRoundTripDelay},
		{"always/spin", spillOptions{alwaysRestore: true}, false, 0},
		{"novector/spin", spillOptions{noVector: true}, false, 0},
		{"novector/sleep", spillOptions{noVector: true}, false, sleepRoundTripDelay},
		{"vector-live/spin", spillOptions{}, true, 0},
		{"always-live/spin", spillOptions{alwaysRestore: true}, true, 0},
		{"novector-live/spin", spillOptions{noVector: true}, true, 0},
	} {
		b.Run(c.name, func(b *testing.B) { benchmarkFastPathRoundTrip(b, c.opts, c.live, c.delay) })
	}
}

func benchmarkFastPathRoundTrip(b *testing.B, opts spillOptions, live bool, delay time.Duration) {
	p := newFastPlatform(b)
	if opts != (spillOptions{}) {
		sc, err := buildSpillWith(opts)
		if err != nil {
			b.Fatal(err)
		}
		// The address space copies the routine when it starts, so the new
		// routine reaches the stub of the rig below.
		p.spill = sc
	}
	r := newRig(b, p)
	var prologue []byte
	if live {
		prologue = gLiveVectorState()
	}
	r.program(prologue, gSyscall(1), gJump(codeVA))
	// The first call patches the page and creates the thread.
	si, _, err := r.run()
	mustSyscall(b, si, err, 1, r.ac)
	f := fastStats(b, r)

	// The runtime clock of Windows can tick every 0.5 ms. A round trip is far
	// shorter, and the end of a delay loop lines up with a tick, so the
	// benchmark reads the performance counter directly.
	delayTicks := uint64(delay) * sentrytime.CounterFrequencyHz() / uint64(time.Second)
	var inSwitch uint64
	sleeps0, wakes0 := f.slot.sleeps.Load(), f.slot.wakes.Load()
	b.ResetTimer()
	for range b.N {
		if delay > 0 {
			for start := sentrytime.ReadCounterTicks(); sentrytime.ReadCounterTicks()-start < delayTicks; {
			}
			if f.slot.sm.stubWaiter().Load() == 0 {
				b.Fatal("the stub did not sleep before the resume")
			}
		}
		setRet(r.ac, 0)
		start := sentrytime.ReadCounterTicks()
		si, _, err := r.run()
		inSwitch += sentrytime.ReadCounterTicks() - start
		if si != nil || err != nil {
			b.Fatalf("Switch = (%s, %v), want a system call", describe(si), err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(inSwitch)*1e9/float64(sentrytime.CounterFrequencyHz())/float64(b.N), "ns/roundtrip")
	b.ReportMetric(float64(f.slot.sleeps.Load()-sleeps0)/float64(b.N), "sentry-sleeps/op")
	b.ReportMetric(float64(f.slot.wakes.Load()-wakes0)/float64(b.N), "stub-wakes/op")
	if got, want := f.traps.Load(), uint64(b.N)+1; got != want {
		b.Fatalf("the fast path served %d of %d system calls", got, want)
	}
	if got := f.colds.Load(); got != 0 {
		b.Fatalf("%d resumes ended in a debug stop, want none", got)
	}
}

// BenchmarkFastPathSpinSweep shows how the spin windows decide between the
// spin path and the event path. Each case sets the number of polls of the
// Sentry and of the stub, and the time that the Sentry holds the trap before it
// answers. The work stands for the time that the Sentry needs to serve a real
// system call. The metrics sentry-sleeps/op and stub-wakes/op count the round
// trips in which a side gave up polling and used an event. A zero count means
// that the spin windows covered the other side.
//
// The windows are loop counts, so their length in time depends on the cost of
// one poll. A pause instruction on x86 takes tens of cycles. A yield instruction
// on arm64 can take one. The sweep therefore reads differently on each
// architecture.
//
// go test -run '^$' -bench BenchmarkFastPathSpinSweep -benchtime 1s ./pkg/sentry/platform/systrap/
func BenchmarkFastPathSpinSweep(b *testing.B) {
	type spin struct{ sentry, stub int }
	spins := []spin{{512, 1024}, {4096, 1024}, {512, 16384}, {4096, 16384}, {32768, 60000}}
	for _, work := range []time.Duration{0, 5 * time.Microsecond, 50 * time.Microsecond} {
		for _, s := range spins {
			name := fmt.Sprintf("work=%v/sentry=%d/stub=%d", work, s.sentry, s.stub)
			b.Run(name, func(b *testing.B) { benchmarkSpinSweep(b, s.sentry, s.stub, work) })
		}
	}
}

func benchmarkSpinSweep(b *testing.B, sentry, stub int, work time.Duration) {
	prev := sentrySpin
	sentrySpin = sentry
	b.Cleanup(func() { sentrySpin = prev })
	p := newFastPlatform(b)
	sc, err := buildSpillWith(spillOptions{spinStub: stub})
	if err != nil {
		b.Fatal(err)
	}
	p.spill = sc
	r := newRig(b, p)
	r.program(gSyscall(1), gJump(codeVA))
	si, _, err := r.run()
	mustSyscall(b, si, err, 1, r.ac)
	f := fastStats(b, r)

	freq := sentrytime.CounterFrequencyHz()
	workTicks := uint64(work) * freq / uint64(time.Second)
	sleeps0, wakes0 := f.slot.sleeps.Load(), f.slot.wakes.Load()
	var inSwitch uint64
	b.ResetTimer()
	for range b.N {
		// The Sentry holds the trap for work, then answers.
		for start := sentrytime.ReadCounterTicks(); sentrytime.ReadCounterTicks()-start < workTicks; {
		}
		setRet(r.ac, 0)
		start := sentrytime.ReadCounterTicks()
		si, _, err := r.run()
		inSwitch += sentrytime.ReadCounterTicks() - start
		if si != nil || err != nil {
			b.Fatalf("Switch = (%s, %v), want a system call", describe(si), err)
		}
	}
	b.StopTimer()
	n := float64(b.N)
	b.ReportMetric(float64(inSwitch)*1e9/float64(freq)/n, "ns/roundtrip")
	b.ReportMetric(float64(f.slot.sleeps.Load()-sleeps0)/n, "sentry-sleeps/op")
	b.ReportMetric(float64(f.slot.wakes.Load()-wakes0)/n, "stub-wakes/op")
}

// BenchmarkSpinWindowDuration measures how long the spin windows last in time.
// The stub window is the time from the trap to the moment that the stub sets
// StubWaiter, with a Sentry that does not answer. The Sentry window is the time
// that await polls before it sleeps. Both are loop counts, so the time depends
// on the cost of one poll on the host. The metrics are ns/window.
func BenchmarkSpinWindowDuration(b *testing.B) {
	freq := sentrytime.CounterFrequencyHz()
	b.Run("stub", func(b *testing.B) {
		for _, polls := range []int{winSpinStub, 16384} {
			b.Run(fmt.Sprintf("polls=%d", polls), func(b *testing.B) {
				p := newFastPlatform(b)
				sc, err := buildSpillWith(spillOptions{spinStub: polls})
				if err != nil {
					b.Fatal(err)
				}
				p.spill = sc
				r := newRig(b, p)
				r.program(gSyscall(1), gJump(codeVA))
				si, _, err := r.run()
				mustSyscall(b, si, err, 1, r.ac)
				f := fastStats(b, r)
				var total uint64
				for range b.N {
					setRet(r.ac, 0)
					// Resume, wait for the next trap, and leave the stub trapped. The
					// Sentry then polls StubWaiter and times the window.
					si, _, err := r.run()
					if si != nil || err != nil {
						b.Fatalf("Switch = (%s, %v)", describe(si), err)
					}
					start := sentrytime.ReadCounterTicks()
					for f.slot.sm.stubWaiter().Load() == 0 {
					}
					total += sentrytime.ReadCounterTicks() - start
					// The stub sleeps now. Run does not wake an asleep stub without the
					// event, which the next resume sets.
				}
				b.ReportMetric(float64(total)*1e9/float64(freq)/float64(b.N), "ns/window")
			})
		}
	})
	b.Run("sentry", func(b *testing.B) {
		for _, polls := range []int{winSpinSentry, 4096} {
			b.Run(fmt.Sprintf("polls=%d", polls), func(b *testing.B) {
				var h winSysmsgHeader
				pending := func() bool { return false }
				var total uint64
				for range b.N {
					start := sentrytime.ReadCounterTicks()
					_, _ = h.await(polls, errSignaler{}, pending)
					total += sentrytime.ReadCounterTicks() - start
				}
				b.ReportMetric(float64(total)*1e9/float64(freq)/float64(b.N), "ns/window")
			})
		}
	})
}

// errSignaler fails the first sleep, so await returns after its spin.
type errSignaler struct{}

func (errSignaler) signalHost() error { return nil }
func (errSignaler) waitGuest() error  { return errors.New("no sleep in the benchmark") }

// TestStopThreadReturnsWhenTheThreadWaitsAtAnEvent starts a cold resume and
// kicks the context while the thread is frozen at the trap of the resume. The
// trap is an exception in the code of the spill routine, and only Switch can
// reply to it. Switch calls stopThread before it waits for events, so a
// stopThread that waits for the thread to leave the spill routine never
// returns. Go guests that send preemption signals with tgkill hit this and
// hung on windows-11-arm.
func TestStopThreadReturnsWhenTheThreadWaitsAtAnEvent(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	mem := r.program(gSyscall(1))
	copy(mem[0x100:], gSyscall(7))
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)

	// A changed program counter makes the resume cold.
	r.ac.SetIP(codeVA + 0x100)
	th := r.ctx.th.Load()
	if err := th.start(r.ac, false); err != nil {
		t.Fatal(err)
	}
	if err := th.run(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for th.evQueued.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the cold resume raised no event")
		}
		time.Sleep(time.Millisecond)
	}

	r.ctx.kicked.Store(true)
	done := make(chan struct{})
	go func() {
		r.ctx.stopThread(th)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("stopThread did not return while the thread waited at an event")
	}

	// Serve the event as Switch does, so that the thread runs on to the next
	// system call and the cleanup of the test finds it in the spill routine.
	r.ctx.kicked.Store(false)
	ev, trapped, err := th.waitNext()
	if err != nil || trapped {
		t.Fatalf("waitNext = (trapped %v, %v), want the event of the cold resume", trapped, err)
	}
	if out := r.ctx.handleEvent(r.rctx, r.mm, r.as, th, r.ac, ev); out.done {
		t.Fatalf("the cold resume ended the stop: %+v", out)
	}
	if _, trapped, err := th.waitNext(); err != nil || !trapped {
		t.Fatalf("waitNext = (trapped %v, %v), want the trap of system call 7", trapped, err)
	}
}

// TestKickDuringColdResumeInterruptsTheGuest checks the other half of the fix:
// a kick that stopThread leaves while the thread waits at the trap of a cold
// resume still stops the guest after Switch served the trap.
func TestKickDuringColdResumeInterruptsTheGuest(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	mem := r.program(gSyscall(1))
	copy(mem[0x100:], gCountSpin())
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)

	r.ac.SetIP(codeVA + 0x100) // a cold resume into a loop that never traps
	done := make(chan error, 1)
	go func() {
		si, _, err := r.run()
		if si != nil {
			err = fmt.Errorf("signal %s: %w", describe(si), err)
		}
		done <- err
	}()
	// Kick many times while the resume and the loop run, so some kicks land
	// while the thread waits at the trap of the cold resume.
	for range 200 {
		r.ctx.Interrupt()
		select {
		case err := <-done:
			if !errors.Is(err, platform.ErrContextInterrupt) {
				t.Fatalf("Switch returned %v, want ErrContextInterrupt", err)
			}
			return
		case <-time.After(time.Millisecond):
		}
	}
	t.Fatal("the guest did not stop after 200 kicks")
}
