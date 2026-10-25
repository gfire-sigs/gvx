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
	"fmt"
	"sync"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// rekickInterval is how long kickAndWait waits before it sends the cancel
// again. A cancel that reaches a processor before it enters the guest ends
// the next run, so the second kick only covers a lost cancel.
const rekickInterval = 10 * time.Millisecond

// addrRange is the half-open range [start, end) of guest addresses.
type addrRange struct{ start, end uint64 }

func (r addrRange) contains(addr uint64) bool { return addr >= r.start && addr < r.end }

// vcpu is one virtual processor of the partition.
//
// A Context uses a vcpu only while it runs Switch. The Context that last used
// the vcpu may still own its floating-point state, which stays inside the
// processor until another Context needs the vcpu.
type vcpu struct {
	p      *Platform
	index  uint32
	comm   *CommPage
	commVA uint64

	// regs and exit are scratch buffers for the holder of the vcpu.
	regs *regBatch
	exit []byte

	// busy and fpOwner belong to Platform.mu.
	busy    bool
	fpOwner *Context

	// st is the architecture state that only the holder uses.
	st  vpState
	ids hvcommon.IDRegisters

	// runMu guards inGuest, epoch and alive. cond wakes kickAndWait.
	runMu   sync.Mutex
	cond    *sync.Cond
	inGuest bool
	epoch   uint64
	alive   bool
}

// alignedBuf returns n bytes aligned to align, which is a power of two.
func alignedBuf(n, align int) []byte {
	buf := make([]byte, n+align)
	off := 0
	if rem := int(uintptr(unsafe.Pointer(&buf[0])) & uintptr(align-1)); rem != 0 {
		off = align - rem
	}
	return buf[off : off+n]
}

// newVP creates virtual processor index and prepares it to run the stub.
func newVP(p *Platform, index uint32) (*vcpu, error) {
	v := &vcpu{
		p:      p,
		index:  index,
		comm:   p.kernel.commPage(int(index)),
		commVA: p.kernel.layout.comm(int(index)),
		regs:   newRegBatch(regBatchCap),
		exit:   alignedBuf(exitCtxBufSize, 16),
		ids:    hvcommon.DefaultIDRegisters(),
		alive:  true,
	}
	v.cond = sync.NewCond(&v.runMu)
	if err := p.be.createVP(index); err != nil {
		return nil, fmt.Errorf("whpx: create virtual processor %d: %w", index, err)
	}
	if err := v.archBringUp(); err != nil {
		if derr := p.be.deleteVP(index); derr != nil {
			err = fmt.Errorf("%w (delete failed: %v)", err, derr)
		}
		return nil, fmt.Errorf("whpx: bring up virtual processor %d: %w", index, err)
	}
	return v, nil
}

// destroy deletes the virtual processor. No goroutine may use it afterwards.
func (v *vcpu) destroy() error {
	v.runMu.Lock()
	v.alive = false
	v.runMu.Unlock()
	if err := v.p.be.deleteVP(v.index); err != nil {
		return fmt.Errorf("whpx: delete virtual processor %d: %w", v.index, err)
	}
	return nil
}

// enter marks the processor as running guest code.
func (v *vcpu) enter() {
	v.runMu.Lock()
	v.inGuest = true
	v.runMu.Unlock()
}

// leave marks the processor as outside the guest and wakes kickAndWait.
func (v *vcpu) leave() {
	v.runMu.Lock()
	v.inGuest = false
	v.epoch++
	v.cond.Broadcast()
	v.runMu.Unlock()
}

// cancelLocked sends WHvCancelRunVirtualProcessor. The caller holds runMu.
func (v *vcpu) cancelLocked() {
	if !v.alive {
		return
	}
	if err := v.p.be.cancel(v.index); err != nil {
		log.Warningf("whpx: cancel virtual processor %d: %v", v.index, err)
	}
}

// kickRunning asks a processor that runs guest code to return.
func (v *vcpu) kickRunning() {
	v.runMu.Lock()
	if v.inGuest {
		v.cancelLocked()
	}
	v.runMu.Unlock()
}

// kickAndWait stops guest execution on the processor and returns after the
// run call has returned. Callers use it to invalidate stale translations: a
// processor that enters the guest later reads the new translation state.
func (v *vcpu) kickAndWait() {
	v.runMu.Lock()
	defer v.runMu.Unlock()
	if !v.inGuest {
		return
	}
	epoch := v.epoch
	for v.inGuest && v.epoch == epoch {
		v.cancelLocked()
		t := time.AfterFunc(rekickInterval, func() {
			v.runMu.Lock()
			v.cond.Broadcast()
			v.runMu.Unlock()
		})
		v.cond.Wait()
		t.Stop()
	}
}

// acquire returns a virtual processor that no other Switch uses. It prefers
// the processor that holds the floating-point state of c, then an idle
// processor without state, then any idle processor. It creates processors up
// to the partition limit and blocks when all are busy.
func (p *Platform) acquire(c *Context) (*vcpu, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		if p.closed {
			return nil, errClosed
		}
		v := c.affinityVP()
		if v == nil || v.busy {
			v = p.pickIdle(c)
		}
		if v != nil {
			v.busy = true
			if owner := v.fpOwner; owner != nil && owner != c {
				owner.evict(v)
			}
			return v, nil
		}
		if n := len(p.freeIdx); n > 0 {
			index := p.freeIdx[n-1]
			p.freeIdx = p.freeIdx[:n-1]
			p.mu.Unlock()
			v, err := newVP(p, index)
			p.mu.Lock()
			if err != nil {
				p.freeIdx = append(p.freeIdx, index)
				p.cond.Broadcast()
				return nil, err
			}
			if p.closed {
				err := v.destroy()
				p.freeIdx = append(p.freeIdx, index)
				p.cond.Broadcast()
				return nil, fmt.Errorf("%w%s", errClosed, joinErr(err))
			}
			p.vps = append(p.vps, v)
			v.busy = true
			return v, nil
		}
		if c.kicked.Swap(false) {
			return nil, platform.ErrContextInterrupt
		}
		p.waiters++
		p.cond.Wait()
		p.waiters--
	}
}

func joinErr(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf(" (%v)", err)
}

// pickIdle returns an idle processor, or nil when all are busy. It prefers a
// processor whose floating-point state no Context owns.
func (p *Platform) pickIdle(c *Context) *vcpu {
	var fallback *vcpu
	for _, v := range p.vps {
		if v.busy {
			continue
		}
		if v.fpOwner == nil || v.fpOwner == c {
			return v
		}
		if fallback == nil {
			fallback = v
		}
	}
	return fallback
}

// release returns a virtual processor after a Switch.
func (p *Platform) release(v *vcpu) {
	p.mu.Lock()
	v.busy = false
	p.cond.Broadcast()
	p.mu.Unlock()
}
