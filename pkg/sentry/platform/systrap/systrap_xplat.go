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

//go:build darwin || windows

package systrap

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/interrupt"
)

// PlatformName is the registration name of the unified systrap backend.
const PlatformName = "systrap"

// ErrUnavailable reports that systrap cannot run on this host. Reason names
// the missing prerequisite.
type ErrUnavailable struct {
	// Host names the GOOS/GOARCH pair.
	Host string
	// Reason names the exact missing prerequisite.
	Reason string
}

// Error implements error.
func (e *ErrUnavailable) Error() string {
	return fmt.Sprintf("systrap is unavailable on %s: %s", e.Host, e.Reason)
}

// constructor adapts New to platform.Constructor.
type constructor struct{}

// New implements platform.Constructor.New.
func (constructor) New(platform.Options) (platform.Platform, error) {
	p, err := New()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// PrecompiledSeccompInfo implements platform.Constructor.PrecompiledSeccompInfo.
// macOS and Windows have no seccomp, so the info only names the platform.
func (constructor) PrecompiledSeccompInfo() []platform.SeccompInfo {
	return []platform.SeccompInfo{platform.StaticSeccompInfo{PlatformName: PlatformName}}
}

func init() {
	platform.Register(PlatformName, constructor{})
}

// ProbeInfo describes a stub that Probe started, handshook with and stopped.
type ProbeInfo struct {
	// Arch is the guest architecture that the stub runs, such as "arm64".
	Arch string
	// PageSize is the host VM page size that the stub reported.
	PageSize int
	// StubPID is the host process ID of the template stub.
	StubPID int
	// ProtocolVersion is the Sentry and stub handoff protocol version.
	ProtocolVersion uint32
	// RoundTrip is the mean time of one guest system call round trip,
	// from the guest svc through the Sentry back to the guest.
	RoundTrip time.Duration
	// UserMin and UserMax bound the guest address range. The platform derives
	// them from the layout of the stub task, so they differ between hosts.
	UserMin, UserMax uint64
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
