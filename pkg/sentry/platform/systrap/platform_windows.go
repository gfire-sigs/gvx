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
	"io"
	"math"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
	"golang.org/x/sys/windows"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
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

	// breakAddr is the address of ntdll!DbgBreakPoint, where a new guest
	// thread starts.
	breakAddr uintptr

	// userMin and userMax bound the guest address range.
	userMin, userMax uint64

	// lowWindow tells whether every stub also reserves the low guest window.
	// New decides it once, because the guest range of the platform must not
	// change while guests run.
	lowWindow bool

	closeOnce sync.Once
	closeErr  error
}

var configureOnce sync.Once

// New starts the stub host and returns a Platform. It must run before the
// Sentry locks itself down, because the host is a child process.
func New() (*Platform, error) { return newPlatformWithHost(spawnStubHost) }

// NewBrokered uses two pipe ends supplied by a confined Sentry worker.
// Platform.Close closes both ends. The caller closes them if startup fails.
// The parent creates stubs for this worker through NewStubBroker.
func NewBrokered(requests io.WriteCloser, replies io.ReadCloser) (*Platform, error) {
	if runtime.GOARCH != "arm64" {
		return nil, errors.New("systrap: native syscall confinement requires windows/arm64")
	}
	return newPlatformWithHost(func(debug windows.Handle) (*stubHost, error) {
		return connectStubHost(&stubHost{in: requests, out: replies}, debug)
	})
}

func newPlatformWithHost(startHost func(windows.Handle) (*stubHost, error)) (*Platform, error) {
	configureOnce.Do(configureArch)
	breakAddr, err := dbgBreakPointAddr()
	if err != nil {
		return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("ntdll!DbgBreakPoint is missing: %v", err)}
	}
	dbg, err := newDebugger()
	if err != nil {
		return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the debug object is unavailable: %v", err)}
	}
	host, err := startHost(dbg.obj)
	if err != nil {
		dbg.close()
		return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the stub host did not start: %v", err)}
	}
	p := &Platform{
		host:      host,
		dbg:       dbg,
		breakAddr: breakAddr,
		userMin:   winBase,
		userMax:   internalBase,
	}
	first, err := p.selectLowWindow()
	if err != nil {
		_ = host.close()
		dbg.close()
		return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the confined stub did not initialize: %v", err)}
	}
	p.startPool()
	if first != nil {
		select {
		case p.pool.ready <- first:
		default:
			first.destroy()
		}
	}
	return p, nil
}

// selectLowWindow verifies the initial stub before the platform starts.
// A window collision permits the high window alone. Confinement failures stop startup.
func (p *Platform) selectLowWindow() (*stubProc, error) {
	p.lowWindow, p.userMin = true, lowBase
	sp, err := p.newStubProcFresh()
	if err == nil {
		return sp, nil
	}
	if !errors.Is(err, errWindowTaken) {
		return nil, err
	}
	if traceEvents {
		tracef("systrap: no low guest window: %v", err)
	}
	p.lowWindow, p.userMin = false, winBase
	return p.newStubProcFresh()
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
		p.stopPool()
		p.dbg.mu.Lock()
		stubs := make([]*stubProc, 0, len(p.dbg.procs))
		for _, sp := range p.dbg.procs {
			stubs = append(stubs, sp)
		}
		p.dbg.mu.Unlock()
		for _, sp := range stubs {
			sp.destroy()
		}
		p.closeErr = p.host.close()
		p.dbg.close()
		p.priv.close()
		p.sections.close()
	})
	return p.closeErr
}

// SupportsAddressSpaceIO implements platform.Platform.SupportsAddressSpaceIO.
// The guest memory lives in another process, so the Sentry reaches it through
// the memory file only.
func (*Platform) SupportsAddressSpaceIO() bool { return false }

// MapUnit implements platform.Platform.MapUnit. A view costs the same at any
// size, so the memory manager maps whole mappings at a time.
func (*Platform) MapUnit() uint64 { return 0 }

// MinUserAddress implements platform.Platform.MinUserAddress.
func (p *Platform) MinUserAddress() hostarch.Addr { return hostarch.Addr(p.userMin) }

// MaxUserAddress implements platform.Platform.MaxUserAddress.
func (p *Platform) MaxUserAddress() hostarch.Addr { return hostarch.Addr(p.userMax) }

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

// NewContext implements platform.Platform.NewContext.
func (p *Platform) NewContext(context.Context) platform.Context {
	c := &Context{p: p}
	c.interrupt.Dst = c
	return c
}

// SeccompInfo implements platform.Platform.SeccompInfo.
func (*Platform) SeccompInfo() platform.SeccompInfo {
	return platform.StaticSeccompInfo{PlatformName: PlatformName}
}

// ConcurrencyCount implements platform.Platform.ConcurrencyCount. A thread
// never waits for a free slot, so the platform does not limit concurrency.
func (*Platform) ConcurrencyCount() int { return math.MaxInt }

// Confinement names the confinement that the host applied to the stubs.
func (p *Platform) Confinement() string {
	level := p.host.level
	s := "none"
	if level&confineToken != 0 {
		s = "low-integrity token without privileges, one-process job"
	}
	if level&confineWin32k != 0 {
		s += ", Win32k disabled"
	}
	if level&confineAppContainer != 0 {
		s += ", AppContainer without capabilities"
	}
	if runtime.GOARCH == "arm64" {
		s += ", native syscall instructions sealed"
	}
	return s
}

// errNoAddressSpace reports that the memory manager has no address space of this platform.
var errNoAddressSpace = &platform.ContextError{Err: errors.New("no stub address space"), Errno: 14}

var _ interrupt.Receiver = (*Context)(nil)
