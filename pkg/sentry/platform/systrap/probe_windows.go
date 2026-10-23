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
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/usermem"
)

const probeCalls = 2000

// probeMM is the minimal MemoryManager of Probe.
type probeMM struct {
	usermem.IO
	as platform.AddressSpace
}

func (*probeMM) MMap(context.Context, memmap.MMapOpts) (hostarch.Addr, error) {
	return 0, unix.ENOSYS
}

func (m *probeMM) AddressSpace() platform.AddressSpace { return m.as }

func (*probeMM) FindVMAByName(hostarch.AddrRange, string) (hostarch.Addr, uint64, error) {
	return 0, 0, unix.ENOENT
}

// installCode maps one page of guest code, patched at once, without a memory
// file. Probe uses it, because Probe has no memory manager.
func (as *addressSpace) installCode(ctx context.Context, mm platform.MemoryManager, base uint64, code []byte) error {
	pg, err := as.p.priv.alloc()
	if err != nil {
		return err
	}
	copy(pg.bytes(), code)
	sites, err := as.patchPage(ctx, mm, base, pg.bytes())
	if err != nil {
		as.p.priv.release(pg)
		return err
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if err := as.win.Map(base, blockSize, &pg.chunk.ref, pg.off, viewReadExec); err != nil {
		as.p.priv.release(pg)
		return err
	}
	as.blocks[base] = &execBlock{base: base, state: blockExec, priv: pg, hasPriv: true, sites: sites}
	return flushInstructionCache(as.sp.proc, uintptr(base), blockSize)
}

// installData maps one zeroed page of guest data without a memory file.
func (as *addressSpace) installData(base uint64) error {
	pg, err := as.p.priv.alloc()
	if err != nil {
		return err
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if err := as.win.Map(base, blockSize, &pg.chunk.ref, pg.off, viewReadWrite); err != nil {
		as.p.priv.release(pg)
		return err
	}
	return nil
}

// Probe starts the stub host, runs a short guest program that makes probeCalls
// system calls, and stops everything. It proves that the host starts stubs, that
// the debug object delivers the traps, and how long one round trip takes.
func Probe() (ProbeInfo, error) {
	traceMuted.Store(true)
	defer traceMuted.Store(false)
	p, err := New()
	if err != nil {
		return ProbeInfo{}, err
	}
	defer p.Close()
	info := ProbeInfo{
		Arch:            runtime.GOARCH,
		PageSize:        blockSize,
		ProtocolVersion: hostProtocolVersion,
		UserMin:         p.userMin,
		UserMax:         p.userMax,
	}
	as, err := newAddressSpace(p)
	if err != nil {
		return info, &ErrUnavailable{Host: "windows/" + runtime.GOARCH, Reason: fmt.Sprintf("the stub process failed: %v", err)}
	}
	defer as.Release()
	info.StubPID = int(as.sp.pid)

	const codeAddr, stackAddr = 0x5555_0000_0000, 0x7000_0000_0000
	mm := &probeMM{as: as}
	if err := as.installCode(context.Background(), mm, codeAddr, probeProgram(probeCalls)); err != nil {
		return info, err
	}
	if err := as.installData(stackAddr); err != nil {
		return info, err
	}
	c := p.NewContext(context.Background()).(*Context)
	defer c.Release()
	ac := arch.New(arch.Host)
	ac.SetIP(codeAddr)
	ac.SetStack(stackAddr + blockSize - 0x100)
	var start time.Time
	for calls := 0; ; calls++ {
		si, _, err := c.Switch(context.Background(), mm, ac, -1)
		if si != nil || err != nil {
			return info, fmt.Errorf("guest probe stopped with signal %v, error %v", si, err)
		}
		switch probeSyscallNumber(ac) {
		case 5:
			if calls == 1 {
				// The first call created the thread, so timing starts after it.
				start = time.Now()
			}
		case 6:
			if calls != probeCalls {
				return info, fmt.Errorf("guest made %d calls, want %d", calls, probeCalls)
			}
			info.RoundTrip = time.Since(start) / (probeCalls - 1)
			return info, nil
		default:
			return info, fmt.Errorf("guest probe made unexpected system call %d", probeSyscallNumber(ac))
		}
	}
}
