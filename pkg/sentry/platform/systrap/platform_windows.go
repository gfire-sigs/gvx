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
	"math"
	"math/rand/v2"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/interrupt"
)

// Platform implements platform.Platform with stub processes that run the guest
// natively. The Sentry is the debugger of every stub, so no code of the stub
// runs when the guest traps or faults.
type Platform struct {
	platform.NoCPUPreemptionDetection
	platform.NoCPUNumbers
	platform.UseHostProcessMemoryBarrier

	host *stubHost
	dbg  *debugger
	// pool holds ready stubs. It is nil in a platform that did not start it.
	pool *stubPool

	sections sectionCache
	priv     privPool

	// images caches the headers of the files that guests map as code.
	images imageCache

	// cleanCode records read-only MemoryFile page addresses that were scanned
	// and verified to require zero patches.
	cleanCode sync.Map

	// breakAddr is the address of ntdll!DbgBreakPoint, where a new guest
	// thread starts.
	breakAddr uintptr

	// userMin and userMax bound the guest address range.
	userMin, userMax uint64

	// lowWindow tells whether every stub also reserves the low guest window.
	// New decides it once, because the guest range of the platform must not
	// change while guests run.
	lowWindow bool

	// fast tells whether the platform runs system calls through the fast path.
	// New decides it once, before the first address space.
	fast bool
	// spill is the spill routine of the fast path, and ntSetEvent and ntWait
	// are the addresses of the ntdll functions that it calls.
	spill winSpillCode
	// spin holds the spin windows of the stub and of the Sentry in ticks of the
	// cycle counter.
	spin       spinWindows
	ntSetEvent uint64
	ntWait     uint64

	threadInit atomic.Pointer[func() error]

	closeOnce sync.Once
	closeErr  error
}

// SetThreadInit registers a callback that Switch runs on the calling OS thread
// before serving a guest context.
func (p *Platform) SetThreadInit(fn func() error) {
	if fn == nil {
		p.threadInit.Store(nil)
		return
	}
	p.threadInit.Store(&fn)
}

var configureOnce sync.Once

// New starts the stub host and returns a Platform. It must run before the
// Sentry locks itself down, because the host is a child process.
//
// The fast path is on by default. When this host cannot run it, New falls back
// to the debug path. GVX_SYSTRAP_FASTPATH=1 makes a host that cannot run the
// fast path an error, and GVX_SYSTRAP_FASTPATH=0 turns the fast path off.
func New() (*Platform, error) {
	// A bad spin setting is an error in every mode. Without this check, the auto
	// mode would take it for a host that cannot run the fast path and fall back
	// to the debug path, which is 50 to 200 times slower.
	if _, err := newSpinWindows(0); err != nil {
		return nil, err
	}
	switch fastPathMode {
	case fastPathOff:
		return open(false)
	case fastPathRequired:
		return open(true)
	}
	p, err := open(true)
	if err == nil {
		return p, nil
	}
	if traceEvents {
		tracef("systrap: the fast path is unavailable, so the platform uses the debug path: %v", err)
	}
	if p, err2 := open(false); err2 == nil {
		return p, nil
	} else {
		return nil, err2
	}
}

// open starts the stub host, and it prepares the fast path when fast is true.
// It releases everything that it started when it fails.
func open(fast bool) (*Platform, error) {
	t0 := time.Now()
	configureOnce.Do(configureArch)
	if fast {
		// The calibration of the spin windows takes a few milliseconds. It runs
		// while the stub host starts.
		go spinTicksPerUs()
	}
	breakAddr, err := dbgBreakPointAddr()
	if err != nil {
		return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("ntdll!DbgBreakPoint is missing: %v", err)}
	}
	dbg, err := newDebugger()
	if err != nil {
		return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the debug object is unavailable: %v", err)}
	}
	tHost := time.Now()
	host, err := spawnStubHost(dbg.obj)
	if err != nil {
		dbg.close()
		return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the stub host did not start: %v", err)}
	}
	tPrep := time.Now()
	p := &Platform{
		host:      host,
		dbg:       dbg,
		breakAddr: breakAddr,
		userMin:   winBase,
		userMax:   internalBase,
	}
	if fast {
		if err := p.prepareFast(); err != nil {
			dbg.close()
			_ = host.close()
			return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the fast path is unavailable: %v", err)}
		}
	}
	tLow := time.Now()
	first := p.selectLowWindow()
	tPool := time.Now()
	p.startPool()
	if first != nil {
		select {
		case p.pool.ready <- first:
		default:
			first.destroy()
		}
	}
	tSelf := time.Now()
	if p.fast {
		// A short guest run proves the facts that the Windows documents do not
		// state. A host that fails the run cannot use the fast path.
		if err := p.selfTestFast(); err != nil {
			_ = p.Close()
			return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the fast path failed its self test: %v", err)}
		}
	}
	if traceWatch {
		now := time.Now()
		ms := func(a, b time.Time) float64 { return float64(b.Sub(a)) / 1e6 }
		fmt.Fprintf(os.Stderr, "systrap: open ms: debugger %.1f, stub host %.1f, fast path %.1f, first stub %.1f, pool start %.1f, self test %.1f, total %.1f\n",
			ms(t0, tHost), ms(tHost, tPrep), ms(tPrep, tLow), ms(tLow, tPool), ms(tPool, tSelf), ms(tSelf, now), ms(t0, now))
	}
	return p, nil
}

// selectLowWindow decides whether the stubs of the platform reserve the low
// guest window. It brings up one stub with both windows. If that works, the
// platform keeps the low window, and the stub goes to the pool. If it fails,
// the host places something in the low range. The platform then keeps only the
// high window, and the first guest reports the cause of a failure that is not
// about the window.
func (p *Platform) selectLowWindow() *stubProc {
	p.lowWindow, p.userMin = true, lowBase
	sp, err := p.newStubProcFresh()
	if err == nil {
		return sp
	}
	if traceEvents {
		tracef("systrap: no low guest window: %v", err)
	}
	p.lowWindow, p.userMin = false, winBase
	return nil
}

// UserAddressHole implements platform.AddressHolePlatform.UserAddressHole. The
// range between the low window and the high window belongs to the stub
// process.
func (p *Platform) UserAddressHole() hostarch.AddrRange {
	if !p.lowWindow {
		return hostarch.AddrRange{}
	}
	return hostarch.AddrRange{Start: hostarch.Addr(lowLimit), End: hostarch.Addr(winBase)}
}

// Close terminates every stub process and frees the Sentry-side memory. It is
// idempotent. No AddressSpace of this Platform may be used afterwards.
func (p *Platform) Close() error {
	p.closeOnce.Do(func() {
		if traceWatch {
			fmt.Fprintf(os.Stderr, "systrap: closing, %s\n", statsLine())
			if traceSample {
				printSamples()
			}
		}
		t0 := time.Now()
		p.stopPool()
		t1 := time.Now()
		p.dbg.close()
		t2 := time.Now()
		p.closeErr = p.host.close()
		t3 := time.Now()
		p.priv.close()
		p.sections.close()
		if traceWatch {
			ms := func(a, b time.Time) float64 { return float64(b.Sub(a)) / 1e6 }
			fmt.Fprintf(os.Stderr, "systrap: close ms: pool %.1f, debugger %.1f, stub host %.1f, memory %.1f, total %.1f\n",
				ms(t0, t1), ms(t1, t2), ms(t2, t3), ms(t3, time.Now()), ms(t0, time.Now()))
		}
	})
	return p.closeErr
}

// MapUnit implements platform.Platform.MapUnit. A view costs the same at any
// size, so the memory manager maps whole mappings at a time.
func (*Platform) MapUnit() uint64 { return 0 }

// MinUserAddress implements platform.Platform.MinUserAddress.
func (p *Platform) MinUserAddress() hostarch.Addr { return hostarch.Addr(p.userMin) }

// NewAddressSpace implements platform.Platform.NewAddressSpace. The platform
// starts a stub process for each address space.
func (p *Platform) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	as, err := newAddressSpace(p)
	if err != nil {
		// The Sentry maps an unknown error of a system call to a panic. A
		// failed fork or exec reports ENOMEM.
		return nil, &platform.ContextError{Err: err, Errno: unix.ENOMEM}
	}
	return as, nil
}

// Confinement names the confinement that the host applied to the stubs.
func (p *Platform) Confinement() string {
	level := p.host.level
	s := "none"
	if level&confineToken != 0 {
		s = "restricted low-integrity token, one-process job"
	}
	if level&confineWin32k != 0 {
		s += ", Win32k disabled"
	}
	if level&confineStrict != 0 {
		s += ", strict handle checks, extension points disabled"
	}
	return s
}

const probeCalls = 2000

// runProbeLoop executes the guest probe loop at codeAddr with stackAddr and
// returns the mean round-trip duration across probeCalls-1 calls.
func runProbeLoop(p *Platform, mm platform.MemoryManager, codeAddr, stackAddr uint64) (time.Duration, error) {
	c := p.NewContext(context.Background()).(*Context)
	defer c.Release()
	ac := arch.New(arch.Host)
	ac.SetIP(uintptr(codeAddr))
	ac.SetStack(uintptr(stackAddr + blockSize - 0x100))
	var start time.Time
	for calls := 0; ; calls++ {
		si, _, err := c.Switch(context.Background(), mm, ac, -1)
		if si != nil || err != nil {
			return 0, fmt.Errorf("guest probe stopped with signal %v, error %v", si, err)
		}
		switch num := probeSyscallNumber(ac); num {
		case 5:
			if calls == 1 {
				start = time.Now()
			}
		case 6:
			if calls != probeCalls {
				return 0, fmt.Errorf("guest made %d calls, want %d", calls, probeCalls)
			}
			return time.Since(start) / (probeCalls - 1), nil
		default:
			return 0, fmt.Errorf("guest probe made unexpected system call %d", num)
		}
	}
}

// islandReach is the largest distance between a patched instruction and the
// island that holds its slot. A B instruction reaches 128MiB on arm64, and the
// margin covers the island size and the slot branch back.
const islandReach = 120 << 20

// blockState says which mapping of a guest block the stub currently sees.
type blockState uint8

const (
	// blockData maps the original frame without execute permission.
	blockData blockState = iota
	// blockExec maps a patched private copy as read and execute.
	blockExec
)

var (
	errAddressSpaceReleased = errors.New("the address space is released")
	errPatchRaced           = errors.New("the block changed while it was patched")
	errNoAddressSpace       = &platform.ContextError{Err: errors.New("no stub address space"), Errno: unix.EFAULT}
)

// AlignmentError reports a mapping request that the host page cannot honor.
type AlignmentError struct {
	Op   string
	Addr uint64
	Len  uint64
}

// Error implements error.
func (e *AlignmentError) Error() string {
	return fmt.Sprintf("%s [%#x, %#x) is not aligned to the %dKB host page", e.Op, e.Addr, e.Addr+e.Len, blockSize/1024)
}

func blockRound(n uint64) uint64 { return n &^ (blockSize - 1) }

func checkAligned(op string, addr, length uint64) error {
	if length == 0 || addr%blockSize != 0 || length%blockSize != 0 {
		return &AlignmentError{Op: op, Addr: addr, Len: length}
	}
	return nil
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// SupportsAddressSpaceIO implements platform.Platform.SupportsAddressSpaceIO.
// The guest memory lives in another process, so the Sentry reaches it through
// the memory file only.
func (*Platform) SupportsAddressSpaceIO() bool { return false }

// MaxUserAddress implements platform.Platform.MaxUserAddress.
func (p *Platform) MaxUserAddress() hostarch.Addr { return hostarch.Addr(p.userMax) }

// NewContext implements platform.Platform.NewContext.
func (p *Platform) NewContext(context.Context) platform.Context {
	c := &Context{p: p}
	c.interrupt = interrupt.Forwarder{Dst: c}
	return c
}

// SeccompInfo implements platform.Platform.SeccompInfo.
func (*Platform) SeccompInfo() platform.SeccompInfo {
	return platform.StaticSeccompInfo{PlatformName: PlatformName}
}

// ConcurrencyCount implements platform.Platform.ConcurrencyCount. Each guest
// thread has its own host thread, so the platform never makes Switch wait.
func (*Platform) ConcurrencyCount() int { return math.MaxInt }

// PatchedBlocks returns how many code blocks this address space patched.
func (as *addressSpace) PatchedBlocks() uint64 { return as.patchedBlocks.Load() }

// PreFork implements platform.AddressSpace.PreFork.
func (*addressSpace) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (*addressSpace) PostFork() {}

// blockStateOf reports whether base is an exec block and its state.
func (as *addressSpace) blockStateOf(base uint64) (blockState, hostarch.AccessType, bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[base]
	if blk == nil {
		return 0, hostarch.NoAccess, false
	}
	return blk.state, blk.at, true
}

// inPatchedCode reports whether pc lies in a patched copy that the stub runs.
func (as *addressSpace) inPatchedCode(pc uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[blockRound(pc)]
	return blk != nil && blk.state == blockExec
}

// inIsland reports whether pc lies in an island.
func (as *addressSpace) inIsland(pc uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	_, ok := as.islands[blockRound(pc)]
	return ok
}

func (as *addressSpace) dropReservation(base uint64) {
	as.mu.Lock()
	delete(as.reserved, base)
	as.mu.Unlock()
}

// newIslandAt reserves a sealed mapping within islandReach of near through the
// memory manager and installs a private page of slots at the stub address that
// candToStub returns.
func (as *addressSpace) newIslandAt(ctx context.Context, mm platform.MemoryManager, near uint64, candToStub func(cand uint64) (uint64, bool)) error {
	var lastErr error
	for range 128 {
		off := (uint64(rand.Int64N(islandReach-(4<<20))) + 2<<20) &^ (blockSize - 1)
		var cand uint64
		if rand.IntN(2) == 0 {
			if near < off {
				continue
			}
			cand = near - off
		} else {
			cand = near + off
		}
		cand = blockRound(cand)
		stubCand, ok := candToStub(cand)
		if !ok {
			continue
		}
		as.mu.Lock()
		if _, busy := as.reserved[stubCand]; busy || as.islands[stubCand] != nil || as.released {
			as.mu.Unlock()
			continue
		}
		as.reserved[stubCand] = struct{}{}
		as.mu.Unlock()

		_, err := mm.MMap(ctx, memmap.MMapOpts{
			Length:    blockSize,
			Addr:      hostarch.Addr(cand),
			Fixed:     true,
			NoReplace: true,
			Private:   true,
			Name:      "[systrap]",
			Sealed:    true,
			Perms:     hostarch.AccessType{Read: true, Execute: true},
			MaxPerms:  hostarch.AccessType{Read: true, Execute: true},
		})
		if err != nil {
			as.dropReservation(stubCand)
			lastErr = err
			continue
		}
		return as.installIsland(stubCand)
	}
	if lastErr == nil {
		lastErr = unix.ENOMEM
	}
	return fmt.Errorf("find an address within 120MiB for a trampoline island: %w", lastErr)
}

// FullStateChanged implements platform.Context.FullStateChanged.
func (c *Context) FullStateChanged() {
	c.needRestoreFP = true
	c.fpInStub = false
}

// Interrupt implements platform.Context.Interrupt.
func (c *Context) Interrupt() {
	c.interrupt.NotifyInterrupt()
}

// Preempt implements platform.Context.Preempt. Switch never waits for a free
// slot, so there is nothing to preempt.
func (*Context) Preempt() {}

// Release implements platform.Context.Release.
func (c *Context) Release() {
	if th := c.th.Swap(nil); th != nil {
		th.destroy()
	}
}

// PrepareSleep implements platform.Context.PrepareSleep.
func (*Context) PrepareSleep() {}

// PrepareUninterruptibleSleep implements platform.Context.PrepareUninterruptibleSleep.
func (*Context) PrepareUninterruptibleSleep() {}

// PrepareStop implements platform.Context.PrepareStop.
func (*Context) PrepareStop() {}

// PrepareExecve implements platform.Context.PrepareExecve.
func (*Context) PrepareExecve() {}

// PrepareExit implements platform.Context.PrepareExit.
func (*Context) PrepareExit() {}

var _ interrupt.Receiver = (*Context)(nil)
