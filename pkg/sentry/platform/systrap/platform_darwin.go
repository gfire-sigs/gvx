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

//go:build darwin && arm64

// The darwin/arm64 systrap backend runs guest code natively in separate stub
// tasks. Each AddressSpace is one stub task, forked from a template process
// that the Sentry spawns before it locks itself down. A guest thread is a Mach
// thread of the stub task. The Sentry and the thread exchange registers
// through a sysmsg page that both map, and wake each other with __ulock.
//
// Three macOS facts shape the design. The stub image is a normal dyld-linked
// Mach-O, because the kernel kills a static arm64 executable. Every arm64 task
// has a 4GB PAGEZERO, so guest addresses start above 4GB. The kernel runs a
// guest `svc #0` as a host system call and clobbers TPIDR_EL0 and X18, so the
// patcher rewrites those instructions. See patcher_arm64_xplat.go.
package systrap

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

const (
	// userFloor is the lowest address that a guest may ever use. The stub
	// image, its heap, dyld and the shared cache occupy the range from 4GB to
	// 12GB. The constant leaves room for their ASLR slide. It also keeps
	// ET_EXEC guests, which link at 0x400000, out of an address space that
	// cannot hold them. The Platform raises the real limit above every
	// reservation of the host kernel. See userRangeFromRegions.
	userFloor = 0x4_0000_0000

	// sysBase is the first address of the per-thread sysmsg blocks in a stub
	// task. Guests cannot map at or above it.
	sysBase = 0x7fff_c000_0000

	// sysSize bounds the guest threads of one stub task.
	sysSize = 0x1000_0000

	// maxThreadBlocks is the number of sysmsg blocks that fit in sysSize.
	maxThreadBlocks = sysSize / threadSpan
)

// ErrUnsupportedPageSize reports a build whose guest page size differs from
// the 16KB host VM page size.
type ErrUnsupportedPageSize struct {
	// GuestPage is hostarch.PageSize.
	GuestPage int
	// HostPage is the host VM page size.
	HostPage int
}

// Error implements error.
func (e *ErrUnsupportedPageSize) Error() string {
	return fmt.Sprintf("systrap on darwin/arm64 needs hostarch.PageSize == host VM page size (%dKB): build with -tags pagesize_16k (hostarch.PageSize is %d, host page size is %d)",
		e.HostPage/1024, e.GuestPage, e.HostPage)
}

// Platform implements platform.Platform with native stub tasks.
type Platform struct {
	platform.NoCPUPreemptionDetection
	platform.NoCPUNumbers
	platform.UseHostProcessMemoryBarrier

	pool *pagePool
	host *stubHost

	// userMin and userMax bound the guest address range. No host mapping lies
	// in [userMin, userMax), so every guest mapping in that range succeeds.
	userMin, userMax uint64

	// zone is true when the platform holds a fixed-address executable. See
	// patcher_darwin_arm64_zone.go.
	zone bool

	// images caches the headers of the files that guests map as code.
	images imageCache

	closeOnce sync.Once
	closeErr  error
}

var (
	configureOnce sync.Once
)

// New spawns the template stub process and returns a Platform. It must run
// before the Sentry locks itself down.
func New() (*Platform, error) {
	if host := unix.Getpagesize(); hostarch.PageSize != blockSize || host != blockSize {
		return nil, &ErrUnsupportedPageSize{GuestPage: hostarch.PageSize, HostPage: host}
	}
	configureOnce.Do(func() { arch.ConfigureAddressSpace(1 << 48) })
	pool := newPagePool()
	host, err := spawnStubHost(pool)
	if err != nil {
		_ = pool.close()
		return nil, err
	}
	userMin, userMax, err := host.userRange()
	if err != nil {
		_ = host.close()
		_ = pool.close()
		return nil, err
	}
	zone := zoneModeRequested()
	if zone {
		if userMin > zoneBias+zoneMin || userMax < zoneBias+zoneLimit+blockSize {
			_ = host.close()
			_ = pool.close()
			return nil, fmt.Errorf("the guest address range [%#x, %#x) cannot hold the zone for fixed-address executables at %#x", userMin, userMax, uint64(zoneBias))
		}
	}
	return &Platform{pool: pool, host: host, userMin: userMin, userMax: userMax, zone: zone}, nil
}

// regionLister reports the first mapping that ends above addr.
type regionLister func(addr uint64) (hostRegion, bool, error)

// userRangeFromRegions returns the widest address range below sysBase that no
// mapping of the stub task touches.
//
// WHY: macOS gives every process permanent PROT_NONE reservations. On Apple
// silicon they cover the 385GB range from 0xfc0000000 to 0x7000000000, and
// they survive mach_vm_deallocate. A guest mapping there fails on the host
// after the Sentry accepted it, and the guest dies with SIGBUS. V8 picks random
// mmap hints and hits the range in about one run in eight. The stub task also
// holds ordinary mappings, and the libmalloc nano zone reserves 512MB near
// 0x600000000000 on a macOS 15 virtual machine. A guest mapping over one of them
// would replace it. The stub cannot allocate after its sandbox starts, so these
// mappings never move. The Sentry has no way to describe a hole inside the user
// address range, so the guest uses one gap. The layout differs between macOS
// releases and machines, so the Platform reads it from the template task.
func userRangeFromRegions(list regionLister) (lo, hi uint64, err error) {
	consider := func(a, b uint64) {
		a = (a + blockSize - 1) &^ (blockSize - 1)
		b = min(b, sysBase) &^ (blockSize - 1)
		if b > a && b-a > hi-lo {
			lo, hi = a, b
		}
	}
	prev := uint64(userFloor)
	for addr := uint64(userFloor); addr < sysBase; {
		r, ok, err := list(addr)
		if err != nil {
			return 0, 0, err
		}
		if !ok || r.start >= sysBase {
			break
		}
		if r.size == 0 {
			return 0, 0, fmt.Errorf("mach_vm_region returned an empty region at %#x", r.start)
		}
		consider(prev, r.start)
		prev = max(prev, r.start+r.size)
		addr = r.start + r.size
	}
	consider(prev, sysBase)
	if hi <= lo {
		return 0, 0, fmt.Errorf("the host leaves no guest address range between %#x and %#x", uint64(userFloor), uint64(sysBase))
	}
	return lo, hi, nil
}

// Close terminates every stub task and frees the Sentry-side memory. It is
// idempotent. No AddressSpace of this Platform may be used afterwards.
func (p *Platform) Close() error {
	p.closeOnce.Do(func() {
		err := p.host.close()
		if perr := p.pool.close(); err == nil {
			err = perr
		}
		p.closeErr = err
	})
	return p.closeErr
}

// MapUnit implements platform.Platform.MapUnit. MapFile maps a whole range with
// one remap and one protection call, so a fault maps up to 256KB of its pma at
// once. A larger unit would map pages that the guest never touches.
func (*Platform) MapUnit() uint64 { return mapUnit }

// MinUserAddress implements platform.Platform.MinUserAddress. In zone mode the
// guest range starts at the bottom of the zone, where a fixed-address
// executable links.
func (p *Platform) MinUserAddress() hostarch.Addr {
	if p.zone {
		return hostarch.Addr(zoneMin)
	}
	return hostarch.Addr(p.userMin)
}

// UserAddressHole implements platform.AddressHolePlatform. In zone mode the
// range between the zone and the first address above the biased zone holds
// either host reservations or the biased copy of the zone, and the memory
// manager must not place a mapping there.
func (p *Platform) UserAddressHole() hostarch.AddrRange {
	if !p.zone {
		return hostarch.AddrRange{}
	}
	return hostarch.AddrRange{Start: zoneLimit, End: zoneBias + zoneLimit}
}

// stubAddr returns the address in the stub task of a guest address.
func (p *Platform) stubAddr(guest uint64) uint64 {
	if p.zone && inZoneGuest(guest) {
		return guest + zoneBias
	}
	return guest
}

// guestAddr returns the guest address of a stub address.
func (p *Platform) guestAddr(stub uint64) uint64 {
	if p.zone && inZoneStub(stub) {
		return stub - zoneBias
	}
	return stub
}

// NewAddressSpace implements platform.Platform.NewAddressSpace. The platform
// patches syscalls always, so the DisableSyscallPatching option has no effect.
func (p *Platform) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return newAddressSpace(p)
}

// mapUnit is the alignment that the memory manager uses to widen a fault.
const mapUnit = 256 << 10
