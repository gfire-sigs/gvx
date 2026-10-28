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

// Package whpx implements a platform on the Windows Hypervisor Platform
// (WinHvPlatform.dll) for windows/amd64 and windows/arm64.
//
// The partition runs only application code. Each virtual processor starts in
// long mode on amd64 and at EL1 on arm64, with a small stub that this package
// generates (stubgen_x86.go and stubgen_a64.go). A system call or a fault
// enters the stub. The stub spills the registers into a per-processor
// CommPage, writes the exit reason and executes HLT (amd64) or HVC #0
// (arm64). The Sentry reads the CommPage, runs the Linux system call and
// resumes the stub. Register calls to the hypervisor are rare. They happen at
// bring-up and on the cold path: floating-point state, clone, signal delivery
// and interrupts that stop the processor in user mode.
//
// The SPEC names bluepill_amd64.s and bluepill_arm64.s for this stub. The
// stub is guest code that runs inside the partition, so the package builds
// its bytes in Go and tests them by decoding. It has no host-side assembly.
//
// Each address space owns its own guest page tables, built with
// pkg/ring0/pagetables. All address spaces share the kernel region: stub
// code, descriptor tables and the CommPages. Guest memory comes from the
// host memory that MapFile receives. The partition maps that memory once, in
// arenas of one guest physical window (gpa.go), and keeps it until Close.
// An address space reaches only the pages that its own page tables name.
package whpx

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	pkgcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// PlatformName is the registration key for the Windows Hypervisor Platform
// backend.
const PlatformName = "whpx"

// Options configures a Platform.
type Options struct {
	// ThreadInit runs on every Context.Switch after the goroutine locks its
	// OS thread. The caller uses it to bind a restricted token to the thread
	// that runs guest code. It runs once per Switch, so it must be cheap and
	// idempotent. A nil ThreadInit does nothing.
	ThreadInit func() error

	// processors overrides the processor count that the partition gets. Tests
	// set it so that they do not depend on the CPU count of the host.
	processors int
}

// errClosed reports a Switch or an address space operation on a closed
// platform.
var errClosed = errors.New("whpx: platform is closed")

// Platform implements platform.Platform on the Windows Hypervisor Platform.
type Platform struct {
	platform.NoCPUPreemptionDetection
	platform.NoCPUNumbers
	platform.UseHostProcessMemoryBarrier

	be      backend
	opts    Options
	arm64   bool
	vpCount int
	info    partitionInfo

	gpa    *gpaAllocator
	mem    *memoryMap
	pool   *ptPool
	kernel *kernelRegion

	// nextASID numbers address spaces. A virtual processor compares the
	// number, not a pointer, to find out whether the last address space it
	// ran is the current one.
	nextASID atomic.Uint64

	// mu guards the fields below and the busy flag of every vcpu.
	mu      sync.Mutex
	cond    *sync.Cond
	vps     []*vcpu
	freeIdx []uint32
	closed  bool

	// waiters counts the goroutines that wait in acquire.
	waiters int

	// closing mirrors closed for readers that hold no lock.
	closing atomic.Bool
}

type constructor struct{}

func (*constructor) New(_ platform.Options) (platform.Platform, error) {
	return New()
}

func (*constructor) PrecompiledSeccompInfo() []platform.SeccompInfo {
	return []platform.SeccompInfo{platform.StaticSeccompInfo{PlatformName: PlatformName}}
}

func init() {
	platform.Register(PlatformName, &constructor{})
}

// New creates a Platform with default options.
func New() (*Platform, error) {
	return NewWithOptions(Options{})
}

// NewWithOptions creates a Platform. It fails closed: any host that cannot
// run the partition, including every non-Windows host, returns an error that
// wraps ErrUnsupported or the failing call.
func NewWithOptions(opts Options) (*Platform, error) {
	if err := checkPageSize(hostarch.PageSize); err != nil {
		return nil, err
	}
	be, err := newBackend()
	if err != nil {
		return nil, err
	}
	return newPlatform(be, opts)
}

// checkPageSize verifies that the Sentry page size equals the page size of the
// partition. The shared page table package builds entries of the Sentry page
// size, so a build with a larger page tag would map larger entries over 4KB
// guest pages.
func checkPageSize(sentryPage int) error {
	if sentryPage != pageSize {
		return fmt.Errorf("%w: the Sentry page size is %d bytes and the partition maps %d-byte pages",
			ErrUnsupported, sentryPage, pageSize)
	}
	return nil
}

// checkHost verifies that the host can run the partition.
func checkHost(arm64 bool, f hostFeatures) error {
	if !f.hypervisorPresent {
		return fmt.Errorf("%w: the hypervisor is not present", ErrUnsupported)
	}
	if !arm64 {
		return nil
	}
	const minBuild, minUBR = 26100, 3915
	if f.windowsBuild < minBuild || (f.windowsBuild == minBuild && f.windowsUBR < minUBR) {
		return fmt.Errorf("%w: windows/arm64 needs build %d.%d or newer, found %d.%d",
			ErrUnsupported, minBuild, minUBR, f.windowsBuild, f.windowsUBR)
	}
	if !f.arm64Support {
		return fmt.Errorf("%w: WHvCapabilityCodeFeatures does not report Arm64Support", ErrUnsupported)
	}
	return nil
}

// newPlatform builds a platform on a backend. It closes the backend partition
// on failure.
func newPlatform(be backend, opts Options) (p *Platform, err error) {
	arm64 := runtime.GOARCH == "arm64"
	feats, err := be.features()
	if err != nil {
		return nil, fmt.Errorf("whpx: query capabilities: %w", err)
	}
	if err := checkHost(arm64, feats); err != nil {
		return nil, err
	}

	vpCount := opts.processors
	if vpCount <= 0 {
		vpCount = min(max(runtime.NumCPU(), 1), maxVPs)
	}
	info, err := be.createPartition(uint32(vpCount))
	if err != nil {
		return nil, fmt.Errorf("whpx: create partition: %w", err)
	}
	p = &Platform{
		be:      be,
		opts:    opts,
		arm64:   arm64,
		vpCount: int(info.vpCount),
		info:    info,
	}
	p.cond = sync.NewCond(&p.mu)
	defer func() {
		if err != nil {
			err = errors.Join(err, p.teardown())
			p = nil
		}
	}()

	archInit()
	p.gpa = newGPAAllocator(gpaWindowBase, gpaTableEnd)
	p.mem = newMemoryMap(be, gpaTableEnd, gpaWindowEnd)
	p.pool = newPTPool(be, p.gpa)
	p.kernel, err = buildKernelRegion(be, p.gpa, p.pool, arm64, p.vpCount)
	if err != nil {
		return p, fmt.Errorf("whpx: build kernel region: %w", err)
	}
	for i := p.vpCount - 1; i >= 0; i-- {
		p.freeIdx = append(p.freeIdx, uint32(i))
	}
	return p, nil
}

// teardown releases the resources of a platform that has no virtual
// processor in the hypervisor any more.
func (p *Platform) teardown() error {
	var errs []error
	if p.mem != nil {
		errs = append(errs, p.mem.close())
	}
	if p.kernel != nil {
		errs = append(errs, p.kernel.release(p.be, p.gpa))
	}
	if p.pool != nil {
		errs = append(errs, p.pool.release())
	}
	errs = append(errs, p.be.closePartition())
	return errors.Join(errs...)
}

// Close stops every virtual processor and deletes the partition. It waits for
// running Switch calls to return and makes later calls fail.
func (p *Platform) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.closing.Store(true)
	vps := append([]*vcpu(nil), p.vps...)
	p.mu.Unlock()

	// A virtual processor in the guest leaves it after the cancel. One that
	// enters the guest later sees the closing flag and returns.
	for _, v := range vps {
		v.kickAndWait()
	}
	p.mu.Lock()
	for p.anyBusy(vps) {
		p.cond.Wait()
	}
	p.mu.Unlock()

	var errs []error
	for _, v := range vps {
		errs = append(errs, v.destroy())
	}
	errs = append(errs, p.teardown())
	return errors.Join(errs...)
}

func (p *Platform) anyBusy(vps []*vcpu) bool {
	for _, v := range vps {
		if v.busy {
			return true
		}
	}
	return false
}

// SupportsAddressSpaceIO implements platform.Platform.SupportsAddressSpaceIO.
// The Sentry reads and writes guest memory through the host mappings of the
// memory file, so the address space has no copy methods.
func (*Platform) SupportsAddressSpaceIO() bool { return false }

// MapUnit implements platform.Platform.MapUnit. One fault maps up to 2 MiB.
// MapFile registers host memory in the partition once. It writes one run of
// page-table entries for each contiguous range.
func (*Platform) MapUnit() uint64 { return 2 << 20 }

// MinUserAddress implements platform.Platform.MinUserAddress.
func (*Platform) MinUserAddress() hostarch.Addr { return hostarch.Addr(minUserAddr) }

// MaxUserAddress implements platform.Platform.MaxUserAddress.
func (p *Platform) MaxUserAddress() hostarch.Addr {
	return hostarch.Addr(p.maxUser())
}

func (p *Platform) maxUser() uint64 {
	if p.arm64 {
		return maxUserAddrA64
	}
	return maxUserAddrX64
}

// NewAddressSpace implements platform.Platform.NewAddressSpace.
func (p *Platform) NewAddressSpace(_ platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return newAddressSpace(p)
}

// NewContext implements platform.Platform.NewContext.
func (p *Platform) NewContext(_ pkgcontext.Context) platform.Context {
	return newContext(p)
}

// ConcurrencyCount implements platform.Platform.ConcurrencyCount. It equals
// the processor count of the partition.
func (p *Platform) ConcurrencyCount() int { return p.vpCount }

// SeccompInfo implements platform.Platform.SeccompInfo.
func (*Platform) SeccompInfo() platform.SeccompInfo {
	return platform.StaticSeccompInfo{PlatformName: PlatformName}
}

// kernelPageTables returns the shared kernel page tables.
func (p *Platform) kernelPageTables() *pagetables.PageTables { return p.kernel.pt }
