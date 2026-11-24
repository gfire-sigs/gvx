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
	"fmt"
	"math/bits"
	"time"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sync"
)

// Limits bounds the GPU resources of one sandbox. A zero field selects its
// default. pkg/gvx sets BlobBytes from Config.GPU.MemoryLimit.
type Limits struct {
	// BlobBytes bounds the host bytes of all live blobs of the sandbox.
	BlobBytes uint64
	// SubmitBytes bounds the total bytes of copied EXECBUFFER and
	// RESOURCE_CREATE_BLOB command buffers in flight on one device. It also
	// counts the BO handle arrays of EXECBUFFER.
	// Tests set a short value.
	SubmitBytes uint64
	// FenceTimeout bounds how long a fence can stay pending before the device
	// marks its context lost. Tests set a short value.
	FenceTimeout time.Duration
	// WaitTimeout bounds one blocking DRM_IOCTL_VIRTGPU_WAIT. Zero selects
	// defaultWaitTimeout. Tests set a short value.
	WaitTimeout time.Duration
}

const (
	defaultBlobBytes    = 4 << 30
	defaultSubmitBytes  = 64 << 20
	defaultFenceTimeout = 30 * time.Second
	defaultWaitTimeout  = 15 * time.Second // Linux virtio_gpu_wait_ioctl: 15 * HZ
	maxContexts         = 64
	maxLiveBlobs        = 65536
	maxHandlesPerFile   = 65536
	maxPendingFences    = 4096
)

func (l Limits) withDefaults() Limits {
	if l.BlobBytes == 0 {
		l.BlobBytes = defaultBlobBytes
	}
	if l.SubmitBytes == 0 {
		l.SubmitBytes = defaultSubmitBytes
	}
	if l.FenceTimeout <= 0 {
		l.FenceTimeout = defaultFenceTimeout
	}
	if l.WaitTimeout <= 0 {
		l.WaitTimeout = defaultWaitTimeout
	}
	return l
}

// roundUpBlobSize rounds a validated blob size (<= maxBlobBytes) up to a
// multiple of blobAlignment.
func roundUpBlobSize(size uint64) uint64 {
	return (size + blobAlignment - 1) &^ (blobAlignment - 1)
}

// roundUpBlobSizeChecked rounds size up to a multiple of blobAlignment and
// reports false when the addition overflows uint64.
func roundUpBlobSizeChecked(size uint64) (uint64, bool) {
	sum, carry := bits.Add64(size, blobAlignment-1, 0)
	if carry != 0 {
		return 0, false
	}
	return sum &^ (blobAlignment - 1), true
}

// submitByteBudget bounds total command buffer bytes copied into Sentry memory
// across all concurrent submitters of one Device. mu is a leaf lock; callers
// never hold another virtgpu lock while acquiring it.
type submitByteBudget struct {
	limit uint64

	mu sync.Mutex
	// +checklocks:mu
	used uint64
	// +checklocks:mu
	notify chan struct{}
}

// acquire reserves n bytes from b, blocking until room is available or ctx is
// interrupted. It returns ENOMEM when n exceeds b.limit and ERESTARTSYS on
// signal interruption.
func (b *submitByteBudget) acquire(ctx context.Context, n uint64) error {
	if n == 0 {
		return nil
	}
	if n > b.limit {
		return linuxerr.ENOMEM
	}
	for {
		b.mu.Lock()
		if b.used <= b.limit-n {
			b.used += n
			b.mu.Unlock()
			return nil
		}
		ch := b.notify
		if ch == nil {
			ch = make(chan struct{})
			b.notify = ch
		}
		b.mu.Unlock()

		if err := ctx.Block(ch); err != nil {
			return linuxerr.ERESTARTSYS
		}
	}
}

// release returns n bytes to b and wakes blocked waiters.
func (b *submitByteBudget) release(n uint64) {
	if n == 0 {
		return
	}
	b.mu.Lock()
	if n > b.used {
		used := b.used
		b.mu.Unlock()
		panic(fmt.Sprintf("virtgpu: submit byte budget underflow (%d > %d)", n, used))
	}
	b.used -= n
	ch := b.notify
	b.notify = nil
	b.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

// blobBudget counts the blobs of one Device and their host bytes. A blob holds
// its share from the reservation before BLOB_CREATE until its memory ends.
// Mappable blobs release on view unmap; non-mappable blobs release on GEM
// handle removal.
type blobBudget struct {
	limit uint64
	bytes atomicbitops.Uint64
	live  atomicbitops.Int64
}

// reserve takes n bytes and one blob. It returns ENOMEM, and takes nothing,
// when either count would pass its limit.
func (b *blobBudget) reserve(n uint64) error {
	for {
		cur := b.live.Load()
		if cur >= maxLiveBlobs {
			return linuxerr.ENOMEM
		}
		if b.live.CompareAndSwap(cur, cur+1) {
			break
		}
	}
	for {
		cur := b.bytes.Load()
		if n > b.limit || cur > b.limit-n {
			b.live.Add(-1)
			return linuxerr.ENOMEM
		}
		if b.bytes.CompareAndSwap(cur, cur+n) {
			return nil
		}
	}
}

// grow adds n bytes without a limit check. It runs when the renderer gave a
// bigger object than the reservation.
func (b *blobBudget) grow(n uint64) {
	if n > 0 {
		b.bytes.Add(n)
	}
}

// release gives back n bytes and one blob.
func (b *blobBudget) release(n uint64) {
	if n > 0 {
		b.bytes.Add(^(n - 1))
	}
	if live := b.live.Add(-1); live < 0 {
		panic(fmt.Sprintf("virtgpu: blob live count %d", live))
	}
}
