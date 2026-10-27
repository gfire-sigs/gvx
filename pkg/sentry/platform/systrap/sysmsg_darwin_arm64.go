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

package systrap

import (
	"sync/atomic"
	"unsafe"
)

// These constants mirror stub/gvx_stub.h. The stub reports its own values in
// the hello message and checkHello rejects a stub that disagrees.
const (
	blockSize       = 0x4000
	threadSpan      = 0x10000
	sysmsgSize      = 0x800
	stubStackTop    = 0x1400
	altStackBase    = 0x4000
	altStackSize    = 0xc000
	altStackTop     = 0x10000
	sysmsgMagic     = 0x3174737876673031
	helloMagic      = 0x6f6c6c6568767667
	protocolVersion = 1

	stateNew      = 0
	stateTrapped  = 2
	stateRunHot   = 3
	stateRunCold  = 4
	kindStart     = 1
	kindSyscall   = 2
	kindSignal    = 3
	kindInterrupt = 4

	cmdFork = 1
	cmdExit = 2
	cmdKill = 3

	layoutWords = 15

	// tlsOffset is the offset of the virtual TLS word that patched `mrs` slots read.
	tlsOffset = 24
	// x18Offset, spillOffset, scratchOffset and indTargetOffset locate the
	// virtual x18, the scratch words and the indirect branch target of the sysmsg.
	x18Offset       = 912
	spillOffset     = 920
	scratchOffset   = 928
	indTargetOffset = 1760

	// waiterSentry and waiterStub are the bits of sysmsg.Waiter.
	waiterSentry = 1
	waiterStub   = 2
	// waiterOffset is the offset of Waiter in the sysmsg.
	waiterOffset = 884
	// sentrySpinRounds is the number of procyield rounds of the Sentry before
	// it sleeps on State.
	sentrySpinRounds = 512
	// sentrySpinYields is the number of YIELD instructions in one round.
	sentrySpinYields = 4
)

// mcontext mirrors the Darwin _STRUCT_MCONTEXT64 that the kernel writes into a
// signal frame and that the stub copies into the sysmsg.
type mcontext struct {
	ES armExceptionState
	SS armThreadState
	NS armNeonState
}

// sysmsg mirrors struct gv_sysmsg. One sysmsg per guest thread lives in memory
// that the Sentry and the stub task share. Every field except State is owned
// by whichever side holds the thread. State is the futex word of the handoff.
type sysmsg struct {
	Magic uint64
	State uint32
	Kind  uint32
	Stack uint64
	TLS   uint64
	Tail  uint64
	Sig   uint64
	Addr  uint64
	Code  uint64
	MC    mcontext
	Cold  uint32
	// Waiter holds the bits that tell the other side to call ulock_wake. A side
	// sets its bit before it sleeps on State and clears the bit when it wakes.
	Waiter uint32
	Alt    [3]uint64
	// X18 is the guest x18. The kernel zeroes the real x18 on every return
	// from an exception, so patched code reads and writes this word instead.
	X18 uint64
	// Spill holds the guest scratch register that a patched x18 slot borrows.
	Spill uint64
	// Scratch holds the guest x16 and x17 that a trap or memory slot spills.
	Scratch [2]uint64
	// FMC receives the context of a fault, so that a fault inside the reload
	// code cannot destroy the guest state in MC.
	FMC mcontext
	// IndTarget holds the guest target address of a zero-clobber indirect
	// branch slot in zone mode.
	IndTarget uint64
}

// ctlPage mirrors struct gv_ctl, the command page of the template process.
type ctlPage struct {
	Seq    uint32
	Ack    uint32
	Cmd    uint32
	Result int32
	Cookie uint64
	Arg    uint64
}

// helloPayload mirrors struct gv_hello.
type helloPayload struct {
	Magic          uint64
	Version        uint32
	Kind           uint32
	Cookie         uint64
	PID            uint64
	CtlAddr        uint64
	Spill          uint64
	ThreadEntry    uint64
	InterruptEntry uint64
	TextLo         uint64
	TextHi         uint64
	PageSize       uint64
	Layout         [layoutWords]uint64
}

// expectedLayout lists the layout words in the order that the stub sends them.
func expectedLayout() [layoutWords]uint64 {
	var sm sysmsg
	return [layoutWords]uint64{
		sysmsgSize,
		uint64(unsafe.Offsetof(sm.State)),
		uint64(unsafe.Offsetof(sm.Kind)),
		uint64(unsafe.Offsetof(sm.TLS)),
		uint64(unsafe.Offsetof(sm.Tail)),
		uint64(unsafe.Offsetof(sm.MC)),
		uint64(unsafe.Offsetof(sm.Cold)),
		uint64(unsafe.Offsetof(sm.Alt)),
		uint64(unsafe.Sizeof(sm.MC)),
		stubStackTop,
		altStackTop,
		uint64(unsafe.Sizeof(ctlPage{})),
		uint64(unsafe.Offsetof(sm.X18)),
		uint64(unsafe.Offsetof(sm.Spill)),
		uint64(unsafe.Offsetof(sm.FMC)),
	}
}

var _ = [1]struct{}{}[unsafe.Offsetof(sysmsg{}.Scratch)-scratchOffset]
var _ = [1]struct{}{}[scratchOffset-trapScratchOffset]
var _ = [1]struct{}{}[unsafe.Offsetof(sysmsg{}.IndTarget)-indTargetOffset]

// loadState reads the handoff word with acquire semantics.
func (sm *sysmsg) loadState() uint32 {
	return atomic.LoadUint32(&sm.State)
}

// storeState publishes the handoff word with release semantics.
func (sm *sysmsg) storeState(v uint32) {
	atomic.StoreUint32(&sm.State, v)
}

func (c *ctlPage) loadAck() uint32 { return atomic.LoadUint32(&c.Ack) }
