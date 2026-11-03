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
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"unsafe"
)

// fakeMapping is one live WHvMapGpaRange call of the fake.
type fakeMapping struct {
	host  unsafe.Pointer
	size  uint64
	flags uint32
}

// fakeVP is one virtual processor of the fake partition.
type fakeVP struct {
	index uint32
	regs  map[uint32][2]uint64

	// canceled is the sticky cancel flag of WHvCancelRunVirtualProcessor.
	canceled bool
	running  bool
	runs     int
	cancels  int

	// setCalls records the register names of every setRegs call.
	setCalls [][]uint32
	getCalls [][]uint32

	// xsave is the compacted XSAVE state of the processor.
	xsave     []byte
	xsaveGets int
	xsaveSets int
}

// runScript fills the exit context of one run. A script that returns blockRun
// makes run wait until the processor is cancelled and then report a cancel.
type runScript func(vp *fakeVP, exit []byte) error

var errBlockRun = errors.New("block until cancelled")

// fakeBackend is a scripted hypervisor for tests above the backend seam.
type fakeBackend struct {
	mu   sync.Mutex
	cond *sync.Cond

	feats     hostFeatures
	featErr   error
	createErr error
	vpErr     func(index uint32) error
	runErr    error
	info      partitionInfo

	// flushes counts the calls of flushProcessWriteBuffers.
	flushes int

	// cfg is the configuration of the last createPartition call.
	cfg partitionConfig
	// dropXsave lists the XSAVE features that the partition refuses.
	dropXsave uint64

	// xsaveLayout and xcompBV describe the compacted XSAVE state of every
	// processor. xcompBV lacks the compacted-format bit.
	xsaveLayout *xsaveLayout
	xcompBV     uint64
	// xsaveSetErr fails setXsave.
	xsaveSetErr error

	mapErr   func(gpa uint64) error
	unmapErr func(gpa uint64) error
	getErr   func(index uint32) error
	setErr   func(index uint32) error

	mapped     map[uint64]fakeMapping
	mapCalls   int
	unmapCalls int
	hosts      map[uintptr][]byte
	vps        map[uint32]*fakeVP
	created    int
	deleted    []uint32

	partitionOpen bool
	closeErr      error

	// onRun scripts the exit of each run. The default blocks until cancel.
	onRun runScript

	// cancelCanceled is the exit that a cancelled run reports.
	cancelExit func(buf []byte)
}

func newFakeBackend() *fakeBackend {
	fb := &fakeBackend{
		feats: hostFeatures{
			hypervisorPresent: true,
			arm64Support:      true,
			windowsBuild:      26100,
			windowsUBR:        3915,
			xsaveFeatures:     testXsaveCapability,
		},
		mapped:      map[uint64]fakeMapping{},
		hosts:       map[uintptr][]byte{},
		vps:         map[uint32]*fakeVP{},
		xsaveLayout: testXsaveLayout(),
		xcompBV:     testXcompBV,
	}
	fb.cond = sync.NewCond(&fb.mu)
	return fb
}

func (fb *fakeBackend) features() (hostFeatures, error) { return fb.feats, fb.featErr }

func (fb *fakeBackend) createPartition(cfg partitionConfig) (partitionInfo, error) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.createErr != nil {
		return partitionInfo{}, fb.createErr
	}
	fb.partitionOpen = true
	fb.cfg = cfg
	info := fb.info
	info.vpCount = cfg.vpCount
	info.xsaveFeatures = cfg.xsaveFeatures &^ fb.dropXsave
	return info, nil
}

func (fb *fakeBackend) closePartition() error {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.partitionOpen = false
	return fb.closeErr
}

// allocHost returns memory aligned to 64 KiB, as VirtualAlloc does.
func (fb *fakeBackend) allocHost(size uintptr) ([]byte, error) {
	buf := make([]byte, size+ptSlabSize)
	off := uintptr(0)
	if rem := uintptr(unsafe.Pointer(&buf[0])) & (ptSlabSize - 1); rem != 0 {
		off = ptSlabSize - rem
	}
	mem := buf[off : off+size : off+size]
	fb.mu.Lock()
	fb.hosts[uintptr(unsafe.Pointer(&mem[0]))] = buf
	fb.mu.Unlock()
	return mem, nil
}

func (fb *fakeBackend) freeHost(mem []byte) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	key := uintptr(unsafe.Pointer(&mem[0]))
	if _, ok := fb.hosts[key]; !ok {
		return fmt.Errorf("free of unknown host memory %#x", key)
	}
	delete(fb.hosts, key)
	return nil
}

func (fb *fakeBackend) mapGPA(host unsafe.Pointer, gpa, size uint64, flags uint32) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	// Guest memory always maps with execute permission. Page-table slabs and
	// CommPages do not. The counter then ignores the growth of the slab pool.
	if flags&mapFlagExecute != 0 {
		fb.mapCalls++
	}
	if fb.mapErr != nil {
		if err := fb.mapErr(gpa); err != nil {
			return err
		}
	}
	if gpa&pageMask != 0 || size&pageMask != 0 || size == 0 || uintptr(host)&pageMask != 0 {
		return fmt.Errorf("unaligned map gpa=%#x size=%#x host=%p", gpa, size, host)
	}
	for at, m := range fb.mapped {
		if gpa < at+m.size && at < gpa+size {
			return fmt.Errorf("map of gpa=%#x size=%#x overlaps the mapping at %#x size %#x", gpa, size, at, m.size)
		}
	}
	fb.mapped[gpa] = fakeMapping{host: host, size: size, flags: flags}
	return nil
}

func (fb *fakeBackend) unmapGPA(gpa, size uint64) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.unmapCalls++
	if fb.unmapErr != nil {
		if err := fb.unmapErr(gpa); err != nil {
			return err
		}
	}
	m, ok := fb.mapped[gpa]
	if !ok || m.size != size {
		return fmt.Errorf("unmap of gpa=%#x size=%#x does not match a mapping", gpa, size)
	}
	delete(fb.mapped, gpa)
	return nil
}

// mappingOf returns the mapping that covers gpa and the host address that
// gpa translates to.
func (fb *fakeBackend) mappingOf(gpa uint64) (fakeMapping, unsafe.Pointer, bool) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	for at, m := range fb.mapped {
		if gpa >= at && gpa < at+m.size {
			return m, unsafe.Add(m.host, gpa-at), true
		}
	}
	return fakeMapping{}, nil, false
}

// calls returns the number of mapGPA and unmapGPA calls so far.
func (fb *fakeBackend) calls() (maps, unmaps int) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return fb.mapCalls, fb.unmapCalls
}

func (fb *fakeBackend) createVP(index uint32) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.vpErr != nil {
		if err := fb.vpErr(index); err != nil {
			return err
		}
	}
	if _, ok := fb.vps[index]; ok {
		return fmt.Errorf("virtual processor %d exists", index)
	}
	fb.created++
	vp := &fakeVP{index: index, regs: map[uint32][2]uint64{}}
	_, end, err := fb.xsaveLayout.compactedOffsets(fb.xcompBV)
	if err != nil {
		return err
	}
	// A new processor holds every component in its initial state.
	vp.xsave = make([]byte, end)
	binary.LittleEndian.PutUint32(vp.xsave[fxOffMXCSR:], 0x1F80)
	binary.LittleEndian.PutUint32(vp.xsave[fxOffMXCSRMask:], 0xFFFF)
	binary.LittleEndian.PutUint64(vp.xsave[xsaveOffXcompBV:], fb.xcompBV|xcompBVCompacted)
	fb.vps[index] = vp
	return nil
}

func (fb *fakeBackend) deleteVP(index uint32) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	vp, ok := fb.vps[index]
	if !ok {
		return fmt.Errorf("virtual processor %d does not exist", index)
	}
	if vp.running {
		return fmt.Errorf("virtual processor %d is running", index)
	}
	delete(fb.vps, index)
	fb.deleted = append(fb.deleted, index)
	return nil
}

func (fb *fakeBackend) run(index uint32, exit []byte) error {
	fb.mu.Lock()
	vp, ok := fb.vps[index]
	if !ok {
		fb.mu.Unlock()
		return fmt.Errorf("virtual processor %d does not exist", index)
	}
	if vp.running {
		fb.mu.Unlock()
		return fmt.Errorf("virtual processor %d runs twice", index)
	}
	if fb.runErr != nil {
		err := fb.runErr
		fb.mu.Unlock()
		return err
	}
	vp.runs++
	clear(exit)
	if vp.canceled {
		// A cancel that arrived before the run ends the run at once.
		vp.canceled = false
		fb.writeCancel(exit)
		fb.mu.Unlock()
		return nil
	}
	vp.running = true
	fb.cond.Broadcast()
	script := fb.onRun
	fb.mu.Unlock()

	var err error
	if script != nil {
		err = script(vp, exit)
	} else {
		err = errBlockRun
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if errors.Is(err, errBlockRun) {
		for !vp.canceled {
			fb.cond.Wait()
		}
		err = nil
		fb.writeCancel(exit)
	}
	if err == nil && binary.LittleEndian.Uint32(exit) == canceledReason() {
		vp.canceled = false
	}
	vp.running = false
	return err
}

func (fb *fakeBackend) writeCancel(exit []byte) {
	if fb.cancelExit != nil {
		fb.cancelExit(exit)
		return
	}
	writeCancelExit(exit, 3, 0)
}

func (fb *fakeBackend) cancel(index uint32) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	vp, ok := fb.vps[index]
	if !ok {
		return fmt.Errorf("virtual processor %d does not exist", index)
	}
	vp.canceled = true
	vp.cancels++
	fb.cond.Broadcast()
	return nil
}

func (fb *fakeBackend) flushProcessWriteBuffers() {
	fb.mu.Lock()
	fb.flushes++
	fb.mu.Unlock()
}

func (fb *fakeBackend) getRegs(index uint32, b *regBatch) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.getErr != nil {
		if err := fb.getErr(index); err != nil {
			return err
		}
	}
	vp, ok := fb.vps[index]
	if !ok {
		return fmt.Errorf("virtual processor %d does not exist", index)
	}
	names, vals := b.view()
	vp.getCalls = append(vp.getCalls, append([]uint32(nil), names...))
	for i, name := range names {
		v := vp.regs[name]
		binary.LittleEndian.PutUint64(vals[i*regValueSize:], v[0])
		binary.LittleEndian.PutUint64(vals[i*regValueSize+8:], v[1])
	}
	return nil
}

func (fb *fakeBackend) setRegs(index uint32, b *regBatch) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.setErr != nil {
		if err := fb.setErr(index); err != nil {
			return err
		}
	}
	vp, ok := fb.vps[index]
	if !ok {
		return fmt.Errorf("virtual processor %d does not exist", index)
	}
	names, vals := b.view()
	vp.setCalls = append(vp.setCalls, append([]uint32(nil), names...))
	for i, name := range names {
		vp.regs[name] = [2]uint64{
			binary.LittleEndian.Uint64(vals[i*regValueSize:]),
			binary.LittleEndian.Uint64(vals[i*regValueSize+8:]),
		}
	}
	return nil
}

func (fb *fakeBackend) getXsave(index uint32, buf []byte) (int, error) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	vp, ok := fb.vps[index]
	if !ok {
		return 0, fmt.Errorf("virtual processor %d does not exist", index)
	}
	if len(buf) < len(vp.xsave) {
		return len(vp.xsave), errXsaveBufferSmall
	}
	vp.xsaveGets++
	return copy(buf, vp.xsave), nil
}

// setXsave accepts only a state that XRSTORS loads: the same size and
// XCOMP_BV as the state of the processor, and no XSTATE_BV bit outside it.
func (fb *fakeBackend) setXsave(index uint32, buf []byte) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.xsaveSetErr != nil {
		return fb.xsaveSetErr
	}
	vp, ok := fb.vps[index]
	if !ok {
		return fmt.Errorf("virtual processor %d does not exist", index)
	}
	if len(buf) != len(vp.xsave) {
		return fmt.Errorf("XSAVE state is %d bytes, want %d", len(buf), len(vp.xsave))
	}
	xcomp := binary.LittleEndian.Uint64(buf[xsaveOffXcompBV:])
	if xcomp != fb.xcompBV|xcompBVCompacted {
		return fmt.Errorf("XSAVE state has XCOMP_BV %#x, want %#x", xcomp, fb.xcompBV|xcompBVCompacted)
	}
	if bv := binary.LittleEndian.Uint64(buf[xsaveOffXstateBV:]); bv&^(fb.xcompBV|xcr0Legacy) != 0 {
		return fmt.Errorf("XSAVE state has XSTATE_BV %#x outside XCOMP_BV %#x", bv, fb.xcompBV)
	}
	if mxcsr := binary.LittleEndian.Uint32(buf[fxOffMXCSR:]); mxcsr&^binary.LittleEndian.Uint32(buf[fxOffMXCSRMask:]) != 0 {
		return fmt.Errorf("XSAVE state has MXCSR %#x with reserved bits", mxcsr)
	}
	copy(vp.xsave, buf)
	vp.xsaveSets++
	return nil
}

// avxOffset returns the offset of the AVX component in the compacted state.
// The layout never changes, so the caller may hold fb.mu.
func (fb *fakeBackend) avxOffset() int {
	offs, _, err := fb.xsaveLayout.compactedOffsets(fb.xcompBV)
	if err != nil {
		panic(err)
	}
	return int(offs[2])
}

// setVector stores the low and high halves of YMMn in the state of a
// processor and marks the SSE and AVX components live.
func (fb *fakeBackend) setVector(index uint32, n int, low, high uint64) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	st := fb.vps[index].xsave
	binary.LittleEndian.PutUint64(st[fxOffXMM+16*n:], low)
	binary.LittleEndian.PutUint64(st[fb.avxOffset()+16*n:], high)
	bv := binary.LittleEndian.Uint64(st[xsaveOffXstateBV:])
	binary.LittleEndian.PutUint64(st[xsaveOffXstateBV:], bv|xcr0SSE|xcr0AVX)
}

// vector returns the low and high halves of YMMn in the state of a processor.
func (fb *fakeBackend) vector(index uint32, n int) (low, high uint64) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	st := fb.vps[index].xsave
	return binary.LittleEndian.Uint64(st[fxOffXMM+16*n:]), binary.LittleEndian.Uint64(st[fb.avxOffset()+16*n:])
}

// waitRunning blocks until processor index is inside a run call.
func (fb *fakeBackend) waitRunning(index uint32) *fakeVP {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	for {
		if vp, ok := fb.vps[index]; ok && vp.running {
			return vp
		}
		fb.cond.Wait()
	}
}

// setReg stores a register value that a later read returns.
func (fb *fakeBackend) setReg(index uint32, name uint32, lo uint64) {
	fb.mu.Lock()
	fb.vps[index].regs[name] = [2]uint64{lo, 0}
	fb.mu.Unlock()
}

// reg returns the low 64 bits of a register that the Sentry wrote.
func (vp *fakeVP) reg(name uint32) uint64 { return vp.regs[name][0] }

// canceledReason is the exit reason of a cancel on the test architecture.
func canceledReason() uint32 {
	if runtime.GOARCH == "arm64" {
		return a64ExitCanceled
	}
	return x64ExitCanceled
}

// writeCancelExit writes a cancel exit. cpl is the amd64 privilege level and
// pc the amd64 RIP. The arm64 context carries neither.
func writeCancelExit(buf []byte, cpl uint8, pc uint64) {
	clear(buf)
	if runtime.GOARCH == "arm64" {
		binary.LittleEndian.PutUint32(buf[a64ExitOffReason:], a64ExitCanceled)
		return
	}
	binary.LittleEndian.PutUint32(buf[x64ExitOffReason:], x64ExitCanceled)
	binary.LittleEndian.PutUint16(buf[x64ExitOffExecState:], uint16(cpl))
	binary.LittleEndian.PutUint64(buf[x64ExitOffRip:], pc)
}

// writeStubExit writes the exit of the stub. pc is the address that the exit
// context reports. On amd64 the exit is HLT. On arm64 it is the EL1 read of
// unbacked GPA zero.
func writeStubExit(buf []byte, pc uint64) {
	clear(buf)
	if runtime.GOARCH == "arm64" {
		binary.LittleEndian.PutUint32(buf[a64ExitOffReason:], a64ExitUnmappedGpa)
		binary.LittleEndian.PutUint64(buf[a64ExitOffHdrPc:], pc)
		binary.LittleEndian.PutUint64(buf[a64ExitOffHdrCpsr:], a64PstateKernel)
		return
	}
	binary.LittleEndian.PutUint32(buf[x64ExitOffReason:], x64ExitHalt)
	binary.LittleEndian.PutUint16(buf[x64ExitOffExecState:], 0)
	binary.LittleEndian.PutUint64(buf[x64ExitOffRip:], pc)
}

// testOptions selects the vector state from the test layout, not from the CPU
// of the host.
func testOptions() Options {
	return Options{xsaveLayout: testXsaveLayout(), fpLimit: sentryFPLimit()}
}

// newTestPlatform builds a platform on a fake backend and closes it at the
// end of the test.
func newTestPlatform(t testing.TB, fb *fakeBackend, opts Options) *Platform {
	t.Helper()
	if opts.processors == 0 {
		// Several tests limit the pool to four processors, and a CI runner can
		// have fewer CPUs than that.
		opts.processors = 8
	}
	if opts.xsaveLayout == nil {
		opts.xsaveLayout, opts.fpLimit = testXsaveLayout(), sentryFPLimit()
	}
	p, err := newPlatform(fb, opts)
	if err != nil {
		t.Fatalf("newPlatform: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return p
}
