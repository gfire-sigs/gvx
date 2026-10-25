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
	"fmt"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
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

	// fast tells whether the platform runs system calls through the fast path.
	// New decides it once, before the first address space.
	fast bool
	// spill is the spill routine of the fast path, and ntSetEvent and ntWait
	// are the addresses of the ntdll functions that it calls.
	spill      winSpillCode
	ntSetEvent uint64
	ntWait     uint64

	closeOnce sync.Once
	closeErr  error
}

var configureOnce sync.Once

// New starts the stub host and returns a Platform. It must run before the
// Sentry locks itself down, because the host is a child process.
//
// The fast path is on by default. When this host cannot run it, New falls back
// to the debug path. GVX_SYSTRAP_FASTPATH=1 makes a host that cannot run the
// fast path an error, and GVX_SYSTRAP_FASTPATH=0 turns the fast path off.
func New() (*Platform, error) {
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
	configureOnce.Do(configureArch)
	breakAddr, err := dbgBreakPointAddr()
	if err != nil {
		return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("ntdll!DbgBreakPoint is missing: %v", err)}
	}
	dbg, err := newDebugger()
	if err != nil {
		return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the debug object is unavailable: %v", err)}
	}
	host, err := spawnStubHost(dbg.obj)
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
	if fast {
		if err := p.prepareFast(); err != nil {
			dbg.close()
			_ = host.close()
			return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the fast path is unavailable: %v", err)}
		}
	}
	first := p.selectLowWindow()
	p.startPool()
	if first != nil {
		select {
		case p.pool.ready <- first:
		default:
			first.destroy()
		}
	}
	if p.fast {
		// A short guest run proves the facts that the Windows documents do not
		// state. A host that fails the run cannot use the fast path.
		if err := p.selfTestFast(); err != nil {
			_ = p.Close()
			return nil, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the fast path failed its self test: %v", err)}
		}
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
		p.stopPool()
		p.dbg.close()
		p.closeErr = p.host.close()
		p.priv.close()
		p.sections.close()
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
