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
	"time"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/arch"
)

const (
	// selfTestCalls is the number of system calls that the self test makes in
	// a loop. The loop counter lives in a guest register, so a call that
	// loses a register changes the number of calls.
	selfTestCalls = 5
	// selfTestTimeout bounds the self test. A routine that hangs in the stub
	// would block New without it.
	selfTestTimeout = 30 * time.Second
)

// selfTestFast proves the fast path on this host. It runs a short guest in a
// new stub and requires that every system call takes the fast path. The fast
// path rests on facts that the documents of Windows do not state: the thread
// register that names the TEB, the TEB words that the spill routine uses, and
// the address of ntdll. A failed run reports the fast path as unavailable.
func (p *Platform) selfTestFast() error {
	as, err := newAddressSpace(p)
	if err != nil {
		return fmt.Errorf("%w: %v", errFastSelfTest, err)
	}
	defer as.Release()
	const codeAddr, stackAddr = 0x5555_0000_0000, 0x7000_0000_0000
	mm := &probeMM{as: as}
	if err := as.installCode(context.Background(), mm, codeAddr, probeProgram(selfTestCalls)); err != nil {
		return fmt.Errorf("%w: %v", errFastSelfTest, err)
	}
	if err := as.installData(stackAddr); err != nil {
		return fmt.Errorf("%w: %v", errFastSelfTest, err)
	}
	c := p.NewContext(context.Background()).(*Context)
	defer c.Release()
	ac := arch.New(arch.Host)
	ac.SetIP(codeAddr)
	ac.SetStack(stackAddr + blockSize - 0x100)

	done := make(chan error, 1)
	go func() { done <- c.runSelfTest(mm, ac) }()
	select {
	case err := <-done:
		return err
	case <-time.After(selfTestTimeout):
		as.sp.destroy()
		<-done
		return fmt.Errorf("%w: no stop within %v", errFastSelfTest, selfTestTimeout)
	}
}

func (c *Context) runSelfTest(mm *probeMM, ac *arch.Context64) error {
	for calls := 0; ; calls++ {
		si, _, err := c.Switch(context.Background(), mm, ac, -1)
		if si != nil || err != nil {
			return fmt.Errorf("%w: the guest stopped with signal %v, error %v", errFastSelfTest, si, err)
		}
		switch probeSyscallNumber(ac) {
		case 5:
		case 6:
			if calls != selfTestCalls {
				return fmt.Errorf("%w: the guest made %d calls, want %d", errFastSelfTest, calls, selfTestCalls)
			}
			th := c.th.Load()
			f := th.fast.Load()
			if f == nil {
				return fmt.Errorf("%w: the thread has no fast slot", errFastSelfTest)
			}
			if got := f.traps.Load(); got != selfTestCalls+1 {
				return fmt.Errorf("%w: %d of %d system calls took the fast path", errFastSelfTest, got, selfTestCalls+1)
			}
			return nil
		default:
			return fmt.Errorf("%w: the guest made unexpected system call %d", errFastSelfTest, probeSyscallNumber(ac))
		}
	}
}
