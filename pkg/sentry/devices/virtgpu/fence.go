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

package virtgpu

import (
	"errors"
	"slices"
	"time"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/waiter"
)

var (
	errContextDead   = errors.New("virtgpu: context dead")
	errTooManyFences = errors.New("virtgpu: pending fence limit reached")
)

// fence is one renderer fence. It signals once: when the renderer retires it
// or a later fence of its ring, when its context ends, or on FenceTimeout.
type fence struct {
	id       uint64
	ring     uint32
	signaled atomicbitops.Bool
	queue    waiter.Queue
	// timer fires fenceTimedOut if f stays pending past FenceTimeout.
	// Assigned under fileContext.fenceMu before f is published to any list.
	timer *time.Timer
}

// signal marks f done, stops its timeout timer, and wakes its waiters. A
// second call does nothing.
func (f *fence) signal() {
	if f.signaled.CompareAndSwap(false, true) {
		if f.timer != nil {
			f.timer.Stop()
		}
		f.queue.Notify(waiter.ReadableEvents)
	}
}

// addPending arms f's timeout timer and appends f to the pending list of
// f.ring. It returns errContextDead when c is dead (I-6b.5) or
// errTooManyFences when c already holds maxPendingFences.
func (c *fileContext) addPending(f *fence, timeout time.Duration, onTimeout func()) error {
	c.fenceMu.Lock()
	defer c.fenceMu.Unlock()
	if c.dead {
		return errContextDead
	}
	if c.pendingCount >= maxPendingFences {
		return errTooManyFences
	}
	f.timer = time.AfterFunc(timeout, onTimeout)
	c.pending[f.ring] = append(c.pending[f.ring], f)
	c.pendingCount++
	return nil
}

// removePending removes f from the pending list of f.ring if present and stops
// its timeout timer.
func (c *fileContext) removePending(f *fence) {
	c.fenceMu.Lock()
	var timer *time.Timer
	list := c.pending[f.ring]
	for i := len(list) - 1; i >= 0; i-- {
		if list[i] == f {
			c.pending[f.ring] = slices.Delete(list, i, i+1)
			c.pendingCount--
			timer = f.timer
			break
		}
	}
	c.fenceMu.Unlock()
	if timer != nil {
		timer.Stop()
	}
}

// retire signals every pending fence on ring whose ID is at most id. Because
// fence IDs enter the list in increasing order (I-6b.3), the retired fences
// form a prefix.
func (c *fileContext) retire(ring uint32, id uint64) {
	if ring >= gpuproto.MaxRings {
		return
	}
	c.fenceMu.Lock()
	list := c.pending[ring]
	cut := 0
	for cut < len(list) && list[cut].id <= id {
		cut++
	}
	var done []*fence
	if cut > 0 {
		done = slices.Clone(list[:cut])
		c.pending[ring] = slices.Delete(list, 0, cut)
		c.pendingCount -= cut
	}
	c.fenceMu.Unlock()

	for _, f := range done {
		f.signal()
	}
}

// failFences marks c dead and signals every pending fence across all rings. It
// is idempotent.
func (c *fileContext) failFences() {
	c.fenceMu.Lock()
	c.dead = true
	var done []*fence
	for i := range c.pending {
		if len(c.pending[i]) == 0 {
			continue
		}
		done = append(done, c.pending[i]...)
		c.pending[i] = nil
	}
	c.pendingCount = 0
	c.fenceMu.Unlock()

	for _, f := range done {
		f.signal()
	}
}

// fenceTimedOut runs when f stayed pending for FenceTimeout. It marks c lost,
// signals every pending fence of c, and sends CTX_DESTROY once. Later calls on
// c get EIO. It takes only fenceMu and no other lock.
func (d *Device) fenceTimedOut(c *fileContext, f *fence) {
	c.fenceMu.Lock()
	if c.dead || !slices.Contains(c.pending[f.ring], f) {
		c.fenceMu.Unlock()
		return
	}
	c.dead = true
	firstLoss := c.lost.CompareAndSwap(false, true)
	var done []*fence
	for i := range c.pending {
		if len(c.pending[i]) == 0 {
			continue
		}
		done = append(done, c.pending[i]...)
		c.pending[i] = nil
	}
	c.pendingCount = 0
	c.fenceMu.Unlock()

	if firstLoss {
		log.Warningf("virtgpu: context %d lost: fence %d on ring %d did not retire within %v", c.id, f.id, f.ring, d.limits.FenceTimeout)
	}
	for _, pf := range done {
		pf.signal()
	}
	d.sendDestroy(c)
}
