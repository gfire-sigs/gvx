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
// The novector variants run a spill routine without the save and the restore of
// the vector state. They give the upper bound of what skipping the vector state
// can save. The routine breaks a guest that uses a vector register, so only
// this benchmark runs it.
//
// Run it through the diagnose workflow with a script, for example:
// go test -run '^$' -bench BenchmarkFastPathRoundTrip -count 5 ./pkg/sentry/platform/systrap/
func BenchmarkFastPathRoundTrip(b *testing.B) {
	for _, vec := range []struct {
		name string
		opts spillOptions
	}{
		{"vector", spillOptions{}},
		{"novector", spillOptions{noVector: true}},
	} {
		for _, wait := range []struct {
			name  string
			delay time.Duration
		}{
			{"spin", 0},
			{"sleep", sleepRoundTripDelay},
		} {
			b.Run(vec.name+"/"+wait.name, func(b *testing.B) {
				benchmarkFastPathRoundTrip(b, vec.opts, wait.delay)
			})
		}
	}
}

func benchmarkFastPathRoundTrip(b *testing.B, opts spillOptions, delay time.Duration) {
	p := newFastPlatform(b)
	if opts.noVector {
		sc, err := buildSpillWith(opts)
		if err != nil {
			b.Fatal(err)
		}
		// The address space copies the routine when it starts, so the new
		// routine reaches the stub of the rig below.
		p.spill = sc
	}
	r := newRig(b, p)
	r.program(gSyscall(1), gJump(codeVA))
	// The first call patches the page and creates the thread.
	si, _, err := r.run()
	mustSyscall(b, si, err, 1, r.ac)
	f := fastStats(b, r)

	// The runtime clock of Windows can tick every 0.5 ms. A round trip is far
	// shorter, and the end of a delay loop lines up with a tick, so the
	// benchmark reads the performance counter directly.
	delayTicks := uint64(delay) * sentrytime.CounterFrequencyHz() / uint64(time.Second)
	var inSwitch uint64
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
	if got, want := f.traps.Load(), uint64(b.N)+1; got != want {
		b.Fatalf("the fast path served %d of %d system calls", got, want)
	}
	if got := f.colds.Load(); got != 0 {
		b.Fatalf("%d resumes ended in a debug stop, want none", got)
	}
}
