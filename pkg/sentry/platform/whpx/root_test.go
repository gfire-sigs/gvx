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

package whpx

import (
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// rootEnv drives one Context on one virtual processor of a fake backend and
// records what the processor sees at each guest entry. The architecture
// files provide newRootEnv and the register name rootReg.
type rootEnv struct {
	t  *testing.T
	fb *fakeBackend
	p  *Platform
	c  *Context
	ac *arch.Context64

	// as is the address space that newRootEnv creates.
	as *AddressSpace

	// stubExit fills the exit of a run like a guest system call.
	stubExit func(vp *fakeVP, exit []byte)

	// stopInReload makes a cancel of the running processor report a stop
	// inside the reload path. The caller invokes it while the processor runs.
	stopInReload func()

	// block makes the next run wait for a cancel.
	block bool

	// entries has one element per run that reached the guest.
	entries []rootEntry
}

// rootEntry is the state of the processor at one guest entry.
type rootEntry struct {
	root  uint64
	flags uint32
}

// install sets the run script of the fake backend.
func (e *rootEnv) install() {
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.entries = append(e.entries, rootEntry{
			root:  vp.reg(rootReg),
			flags: e.p.kernel.commPage(int(vp.index)).Flags.Load(),
		})
		if e.block {
			e.block = false
			return errBlockRun
		}
		e.stubExit(vp, exit)
		return nil
	}
}

func (e *rootEnv) newAS() *AddressSpace { return newTestAS(e.t, e.p) }

// rootWrites counts the register batches that wrote the root register.
func (e *rootEnv) rootWrites() int {
	vp, ok := e.fb.vps[0]
	if !ok {
		return 0
	}
	n := 0
	for _, call := range vp.setCalls {
		for _, name := range call {
			if name == rootReg {
				n++
				break
			}
		}
	}
	return n
}

// switchTo runs one Switch on as. It reports the entry of the run, or false
// when the Switch returned without a guest entry.
func (e *rootEnv) switchTo(as *AddressSpace) (rootEntry, bool, error) {
	e.t.Helper()
	runs := len(e.entries)
	_, _, err := e.c.Switch(nil, &fakeMM{as: as}, e.ac, -1)
	if len(e.entries) == runs {
		return rootEntry{}, false, err
	}
	return e.entries[len(e.entries)-1], true, err
}

// mustEnter runs one Switch that must reach the guest and return without
// error. It also reports whether the Switch wrote the root register.
func (e *rootEnv) mustEnter(as *AddressSpace) (rootEntry, bool) {
	e.t.Helper()
	before := e.rootWrites()
	entry, ran, err := e.switchTo(as)
	if err != nil || !ran {
		e.t.Fatalf("Switch returned %v, ran %v", err, ran)
	}
	return entry, e.rootWrites() > before
}

// wantRoot checks that the entry has the root of as and the reload flag, and
// that the Switch wrote the root register on the host.
func (e *rootEnv) wantRoot(what string, entry rootEntry, written bool, as *AddressSpace) {
	e.t.Helper()
	if entry.root != as.rootValue() {
		e.t.Errorf("%s: root register is %#x at entry, want %#x", what, entry.root, as.rootValue())
	}
	if !written {
		e.t.Errorf("%s: the host did not write the root register", what)
	}
	if entry.flags&flagReloadRoot == 0 {
		e.t.Errorf("%s: flags %#x lack flagReloadRoot", what, entry.flags)
	}
}

func TestSwitchWritesRootRegisterWhenTranslationStateChanges(t *testing.T) {
	e := newRootEnv(t)
	other := e.newAS()
	mem := mustHost(t, e.fb, 1)

	entry, written := e.mustEnter(e.as)
	e.wantRoot("first entry", entry, written, e.as)

	entry, written = e.mustEnter(e.as)
	if written || entry.flags&flagReloadRoot != 0 || entry.root != e.as.rootValue() {
		t.Errorf("unchanged address space: written %v, flags %#x, root %#x", written, entry.flags, entry.root)
	}

	// The processor moves to a second address space and back.
	entry, written = e.mustEnter(other)
	e.wantRoot("second address space", entry, written, other)
	entry, written = e.mustEnter(e.as)
	e.wantRoot("back to the first address space", entry, written, e.as)

	// A new generation of the same address space needs the root again.
	if err := e.as.mapHost(0x400000, mem, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	e.mustEnter(e.as)
	e.as.Unmap(0x400000, pageSize)
	entry, written = e.mustEnter(e.as)
	e.wantRoot("after Unmap", entry, written, e.as)
}

func TestSwitchAbortedByKickWritesRootOnNextEntry(t *testing.T) {
	e := newRootEnv(t)
	other := e.newAS()
	e.mustEnter(e.as)

	// An interrupt that arrives while prepareRun runs makes Switch return
	// before the run. Setting the flag in the register write models the race
	// without a second goroutine. The hook cannot call NotifyInterrupt,
	// because the fake backend holds its lock during a register write.
	kick := true
	e.fb.setErr = func(uint32) error {
		if kick {
			kick = false
			e.c.kicked.Store(true)
		}
		return nil
	}
	_, ran, err := e.switchTo(other)
	if ran || !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("kicked Switch returned %v, ran %v", err, ran)
	}
	e.fb.setErr = nil

	entry, written := e.mustEnter(other)
	e.wantRoot("entry after the kick", entry, written, other)
}

func TestCancelInsideReloadPathWritesRootOnNextEntry(t *testing.T) {
	e := newRootEnv(t)
	e.block = true
	done := make(chan error)
	go func() {
		_, _, err := e.c.Switch(nil, &fakeMM{as: e.as}, e.ac, -1)
		done <- err
	}()
	e.fb.waitRunning(0)
	e.stopInReload()
	e.c.Interrupt()
	if err := <-done; !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("cancelled Switch returned %v", err)
	}

	// The cancel can stop the reload before it loads the root.
	entry, written := e.mustEnter(e.as)
	e.wantRoot("entry after the cancel", entry, written, e.as)
}

func TestReleaseInvalidatesIdleProcessorsThatNameTheAddressSpace(t *testing.T) {
	e := newRootEnv(t)
	other := e.newAS()
	e.mustEnter(e.as)
	v := e.p.vps[0]
	if !v.st.valid || v.st.asID != e.as.id {
		t.Fatalf("processor state %+v does not name the address space", v.st)
	}

	// Releasing an address space that the processor does not name changes
	// nothing.
	other.Release()
	if !v.st.valid || v.st.asID != e.as.id {
		t.Errorf("Release of an unrelated address space changed the state to %+v", v.st)
	}

	// The top-level table of the released address space is recycled, so the
	// processor must not claim to hold it.
	e.as.Release()
	if v.st.valid || v.st.asID != 0 {
		t.Errorf("state %+v still names the released address space", v.st)
	}
}

func TestReleaseLeavesBusyProcessorsToTheirHolder(t *testing.T) {
	e := newRootEnv(t)
	v, err := e.p.acquire(newContext(e.p))
	if err != nil {
		t.Fatal(err)
	}
	// The holder owns the state of a busy processor.
	v.st.valid, v.st.asID = true, e.as.id
	e.as.Release()
	if !v.st.valid || v.st.asID != e.as.id {
		t.Errorf("Release changed the state of a busy processor to %+v", v.st)
	}
	e.p.release(v)
}
