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

// Package hvf implements a macOS Hypervisor.framework platform backend. A
// 4KB Stage-1 page table sits over 16KB Stage-2 host mappings, and an EL1 stub
// exchanges guest state with the Sentry through a shared communication page.
//
// The package builds on every host so the Sentry compiles everywhere. On a
// host other than macOS, New returns an error.
package hvf

import (
	"math"
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

const (
	// PlatformName is the registration key for the macOS Hypervisor.framework backend.
	PlatformName = "hvf"

	pageSize4K = 4096
	pageMask4K = pageSize4K - 1
	pageShift  = 12

	minUserAddr = 0x10000
)

// Platform implements platform.Platform with macOS Hypervisor.framework.
type Platform struct {
	platform.NoCPUPreemptionDetection
	platform.NoCPUNumbers
	platform.UseHostProcessMemoryBarrier

	vm        *vmState
	closeOnce sync.Once
	closeErr  error
}

type constructor struct{}

func (*constructor) New(_ platform.Options) (platform.Platform, error) {
	p, err := New()
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (*constructor) PrecompiledSeccompInfo() []platform.SeccompInfo {
	return []platform.SeccompInfo{platform.StaticSeccompInfo{PlatformName: PlatformName}}
}

func init() {
	platform.Register(PlatformName, &constructor{})
}

// New creates a Platform on the process-wide Hypervisor.framework VM. It
// returns an error when the VM cannot exist, for example when the binary lacks
// the com.apple.security.hypervisor entitlement and cannot sign itself.
func New() (*Platform, error) {
	vm, err := acquireVM()
	if err != nil {
		return nil, err
	}
	return &Platform{vm: vm}, nil
}

// Close stops the vCPU threads of this Platform and destroys the VM when no
// other Platform uses it. Close is idempotent and returns the first result on
// later calls.
func (p *Platform) Close() error {
	p.closeOnce.Do(func() {
		p.closeErr = releaseVM(p.vm)
	})
	return p.closeErr
}

// SupportsAddressSpaceIO implements platform.Platform.SupportsAddressSpaceIO.
// The Sentry reaches guest memory through the memory file mappings, so the
// address space needs no copy methods.
func (*Platform) SupportsAddressSpaceIO() bool {
	return false
}

// mapUnit is the size of the window that one page fault maps. MapFile changes
// only Stage-1 tables over whole contiguous ranges, so a window of 2 MiB costs
// one Stage-2 lookup and up to 512 Stage-1 descriptors. It is a power-of-two
// multiple of hostarch.PageSize, which is 4KB.
const mapUnit = 2 << 20

// MapUnit implements platform.Platform.MapUnit.
func (*Platform) MapUnit() uint64 {
	return mapUnit
}

// MinUserAddress implements platform.Platform.MinUserAddress.
func (*Platform) MinUserAddress() hostarch.Addr {
	return hostarch.Addr(minUserAddr)
}

// MaxUserAddress implements platform.Platform.MaxUserAddress.
func (*Platform) MaxUserAddress() hostarch.Addr {
	return hostarch.Addr(maxUserAddress)
}

// NewAddressSpace implements platform.Platform.NewAddressSpace.
func (p *Platform) NewAddressSpace(_ platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	as, err := newAddressSpace(p.vm)
	if err != nil {
		return nil, err
	}
	return as, nil
}

// NewContext implements platform.Platform.NewContext.
func (p *Platform) NewContext(_ context.Context) platform.Context {
	return newContext(p)
}

// ConcurrencyCount implements platform.Platform.ConcurrencyCount. It is the
// vCPU limit of the VM. The kernel preempts running tasks when more tasks run
// than vCPUs exist, so every task makes progress.
func (p *Platform) ConcurrencyCount() int {
	if n := p.vm.concurrency(); n > 0 {
		return n
	}
	return math.MaxInt
}

// SeccompInfo implements platform.Platform.SeccompInfo.
func (*Platform) SeccompInfo() platform.SeccompInfo {
	return platform.StaticSeccompInfo{PlatformName: PlatformName}
}

// Context implements platform.Context for macOS Hypervisor.framework.
//
// A Context owns no vCPU. Each Switch borrows a vCPU thread from the pool for
// the duration of one guest run. The Sentry-side state in arch.Context64 is
// always complete: every exit copies all registers and the V registers back.
type Context struct {
	platform.NoCPUNumbers

	platform *Platform
	// interrupted is the pending Interrupt flag. Switch consumes it.
	interrupted atomic.Bool
	hw          contextHW
}

func newContext(p *Platform) *Context {
	c := &Context{platform: p}
	c.hw.init()
	return c
}

// Switch implements platform.Context.Switch. The vCPU thread locks its OS
// thread for its whole life, which satisfies the thread-affinity rule of
// hv_vcpu_run, so Switch itself does not lock the caller's thread.
func (c *Context) Switch(ctx context.Context, mm platform.MemoryManager, ac *arch.Context64, _ int32) (*linux.SignalInfo, hostarch.AccessType, error) {
	if c.interrupted.CompareAndSwap(true, false) {
		return nil, hostarch.NoAccess, platform.ErrContextInterrupt
	}
	var as *AddressSpace
	if mm != nil {
		as, _ = mm.AddressSpace().(*AddressSpace)
	}
	if as == nil {
		return nil, hostarch.NoAccess, errNoAddressSpace
	}
	return c.platform.vm.switchContext(ctx, mm, c, as, ac)
}

// PullFullState implements platform.Context.PullFullState. It does nothing
// because every exit already copies the complete register and V register state
// into ac.
//
// WHY: SPEC 3.4 item 1 keeps V0..V31 in the vCPU between exits. This backend
// deliberately differs. A vCPU thread serves many Contexts and a Context moves
// between vCPU threads, so register contents cannot stay in one vCPU. The EL1
// stub spills and reloads the 32 Q registers with 16 store pairs and 16 load
// pairs per exit, which costs well under 100ns.
func (*Context) PullFullState(platform.AddressSpace, *arch.Context64) error {
	return nil
}

// FullStateChanged implements platform.Context.FullStateChanged. Every Switch
// loads the full state from ac, so a Sentry change needs no signal.
func (*Context) FullStateChanged() {}

// Interrupt implements platform.Context.Interrupt. The flag is set before the
// vCPU cancellation so the vCPU thread, which tests the flag after the
// Context becomes visible to Interrupt, never misses it.
func (c *Context) Interrupt() {
	c.interrupted.Store(true)
	c.hw.cancel()
}

// Preempt implements platform.Context.Preempt.
func (c *Context) Preempt() {
	c.Interrupt()
}

// Release implements platform.Context.Release.
func (*Context) Release() {}

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
