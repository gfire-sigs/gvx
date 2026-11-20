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
	"container/heap"
	stdcontext "context"
	"encoding/binary"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/usermem"
)

// blobFlagsKnown is VIRTGPU_BLOB_FLAG_USE_MASK.
const blobFlagsKnown = virtgpuBlobFlagUseMappable | virtgpuBlobFlagUseShareable | virtgpuBlobFlagUseCrossDevice

// gemObject is one GEM handle of a DRM file. Its fields do not change after
// insertion, except mapSlot and lastFence.
type gemObject struct {
	resID     uint32
	blobMem   uint32 // VIRTGPU_BLOB_MEM_HOST3D for venus blobs, 0 for virgl resources
	size      uint64 // requested size rounded up to hostarch.PageSize
	blob      *blob  // nil when the resource is not mappable
	accounted uint64 // reserved bytes for a non-mappable blob; 0 when blob != nil

	// mapSlot is the fake mmap slot that MAP assigned, or 0.
	// Protected by renderFD.gemMu.
	mapSlot uint64

	// lastFence is the newest fence of an EXECBUFFER that listed this object
	// in bo_handles (virgl contexts only), or nil. Protected by renderFD.gemMu.
	lastFence *fence
}

// handleHeap is a min-heap of freed GEM handle numbers.
type handleHeap []uint32

func (h handleHeap) Len() int           { return len(h) }
func (h handleHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h handleHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *handleHeap) Push(x any) {
	*h = append(*h, x.(uint32))
}

func (h *handleHeap) Pop() any {
	old := *h
	n := len(old)
	v := old[n-1]
	*h = old[:n-1]
	return v
}

// gemTable holds the handles of one DRM file. It allocates the lowest free
// handle that is at least 1, as Linux idr_alloc(..., 1, 0, ...) does.
// Protected by renderFD.gemMu.
type gemTable struct {
	objects  map[uint32]*gemObject
	free     handleHeap // freed handles below next, as a min-heap
	next     uint32     // smallest handle never used; starts at 1
	slots    map[uint64]*gemObject
	lastSlot uint64
}

func newGemTable() gemTable {
	return gemTable{
		objects: make(map[uint32]*gemObject),
		next:    1,
		slots:   make(map[uint64]*gemObject),
	}
}

func (t *gemTable) insert(o *gemObject) uint32 {
	if len(t.objects) >= maxHandlesPerFile {
		return 0
	}
	var h uint32
	if len(t.free) > 0 {
		h = heap.Pop(&t.free).(uint32)
	} else {
		if t.next == 0 {
			return 0
		}
		h = t.next
		t.next++
	}
	t.objects[h] = o
	return h
}

func (t *gemTable) lookup(h uint32) (*gemObject, bool) {
	o, ok := t.objects[h]
	return o, ok
}

func (t *gemTable) lookupFence(h uint32) (*fence, bool) {
	o, ok := t.objects[h]
	if !ok {
		return nil, false
	}
	return o.lastFence, true
}

func (t *gemTable) recordFence(objs []*gemObject, f *fence) {
	for _, o := range objs {
		if o.lastFence == nil || o.lastFence.id < f.id {
			o.lastFence = f
		}
	}
}

func (t *gemTable) lookupSlot(slot uint64) *gemObject {
	return t.slots[slot]
}

func (t *gemTable) remove(h uint32) (*gemObject, bool) {
	o, ok := t.objects[h]
	if !ok {
		return nil, false
	}
	delete(t.objects, h)
	if o.mapSlot != 0 {
		delete(t.slots, o.mapSlot)
	}
	heap.Push(&t.free, h)
	return o, true
}

func (t *gemTable) assignSlot(o *gemObject) (uint64, bool) {
	if o.mapSlot != 0 {
		return o.mapSlot, true
	}
	if t.lastSlot >= maxMapSlot {
		return 0, false
	}
	t.lastSlot++
	o.mapSlot = t.lastSlot
	t.slots[o.mapSlot] = o
	return o.mapSlot, true
}

func (t *gemTable) takeAll() []*gemObject {
	if len(t.objects) == 0 {
		return nil
	}
	objs := make([]*gemObject, 0, len(t.objects))
	for _, o := range t.objects {
		objs = append(objs, o)
	}
	clear(t.objects)
	clear(t.slots)
	t.free = nil
	return objs
}

// allocResID returns a resource ID that is not 0 and that d never returned
// before. It returns 0 once the 32-bit space is exhausted.
func (d *Device) allocResID() uint32 {
	for {
		cur := d.lastResID.Load()
		if cur == ^uint32(0) {
			return 0
		}
		if d.lastResID.CompareAndSwap(cur, cur+1) {
			return cur + 1
		}
	}
}

// unrefResource sends RES_UNREF and logs any error at debug level only.
func (d *Device) unrefResource(ctxID, resID uint32) {
	if err := d.renderer.UnrefResource(ctxID, resID); err != nil {
		log.Debugf("virtgpu: unref resource %d on context %d: %v", resID, ctxID, err)
	}
}

// createBlob serves DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB.
func (fd *renderFD) createBlob(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req virtgpuResourceCreateBlob
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}
	if req.BlobFlags&^blobFlagsKnown != 0 {
		return linuxerr.EINVAL
	}
	if req.BlobFlags&virtgpuBlobFlagUseCrossDevice != 0 {
		return linuxerr.EINVAL
	}
	if req.BlobMem != virtgpuBlobMemHost3D {
		return linuxerr.EINVAL
	}
	if req.CmdSize%4 != 0 || req.CmdSize > gpuproto.MaxSubmitBytes {
		return linuxerr.EINVAL
	}
	if req.Size == 0 || req.Size > maxBlobBytes {
		return linuxerr.EINVAL
	}
	guestAddr, ok := hostarch.Addr(req.Size).RoundUp()
	if !ok {
		return linuxerr.EINVAL
	}
	guestSize := uint64(guestAddr)
	c := fd.ctx.Load()
	if c == nil {
		return linuxerr.EINVAL
	}
	if fd.dev.lost.Load() || c.lost.Load() {
		return linuxerr.EIO
	}

	var cmd []byte
	if req.CmdSize > 0 {
		cmd = make([]byte, req.CmdSize)
		if _, err := uio.CopyIn(ctx, hostarch.Addr(req.Cmd), cmd, usermem.IOOpts{}); err != nil {
			return linuxerr.EFAULT
		}
	}

	reserved := roundUpBlobSize(req.Size)
	if err := fd.dev.budget.reserve(reserved); err != nil {
		return err
	}
	taken := false
	defer func() {
		if !taken {
			fd.dev.budget.release(reserved)
		}
	}()

	resID := fd.dev.allocResID()
	if resID == 0 {
		return linuxerr.EIO
	}
	if req.CmdSize > 0 {
		if _, err := fd.dev.submit(c, 0, cmd, false); err != nil {
			return err
		}
	}

	if fd.dev.lost.Load() || c.lost.Load() {
		return linuxerr.EIO
	}
	var res gpuproto.Blob
	err := callRenderer(ctx, func(cc stdcontext.Context) error {
		var callErr error
		res, callErr = fd.dev.renderer.CreateBlob(cc, gpuproto.BlobCreate{
			CtxID:     c.id,
			ResID:     resID,
			BlobMem:   req.BlobMem,
			BlobFlags: req.BlobFlags,
			BlobID:    req.BlobID,
			Size:      req.Size,
		})
		return callErr
	})
	if err != nil {
		if !linuxerr.Equals(linuxerr.ERESTARTSYS, err) && (fd.dev.lost.Load() || c.lost.Load()) {
			return linuxerr.EIO
		}
		return err
	}

	var b *blob
	var objAccounted uint64
	if req.BlobFlags&virtgpuBlobFlagUseMappable != 0 {
		if res.Shm == nil {
			fd.dev.unrefResource(c.id, resID)
			return linuxerr.EIO
		}
		b, err = newBlob(fd.dev, res.Shm, guestSize, reserved)
		if err != nil {
			fd.dev.unrefResource(c.id, resID)
			log.Warningf("virtgpu: map blob %d: %v", resID, err)
			return linuxerr.EIO
		}
		taken = true
	} else {
		if res.Shm != nil {
			if cerr := res.Shm.Close(); cerr != nil {
				log.Warningf("virtgpu: close unexpected blob descriptor: %v", cerr)
			}
			fd.dev.unrefResource(c.id, resID)
			return linuxerr.EIO
		}
		objAccounted = reserved
	}

	obj := &gemObject{
		resID:     resID,
		blobMem:   req.BlobMem,
		size:      guestSize,
		blob:      b,
		accounted: objAccounted,
	}
	fd.gemMu.Lock()
	h := fd.gem.insert(obj)
	fd.gemMu.Unlock()
	if h == 0 {
		fd.dev.unrefResource(c.id, resID)
		if b != nil {
			b.decOwner()
		}
		return linuxerr.ENOMEM
	}
	taken = true

	req.BoHandle = h
	req.ResHandle = resID
	_, _ = binary.Encode(arg, binary.LittleEndian, &req)
	return nil
}

// gemClose serves DRM_IOCTL_GEM_CLOSE.
func (fd *renderFD) gemClose(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req drmGemClose
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}
	if req.Handle == 0 {
		return linuxerr.EINVAL
	}

	fd.gemMu.Lock()
	o, ok := fd.gem.remove(req.Handle)
	fd.gemMu.Unlock()
	if !ok {
		return linuxerr.EINVAL
	}

	if c := fd.ctx.Load(); c != nil {
		fd.dev.unrefResource(c.id, o.resID)
	}
	if o.blob != nil {
		o.blob.decOwner()
	} else if o.accounted != 0 {
		fd.dev.budget.release(o.accounted)
	}
	return nil
}

// resourceInfo serves DRM_IOCTL_VIRTGPU_RESOURCE_INFO.
func (fd *renderFD) resourceInfo(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req virtgpuResourceInfo
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}

	fd.gemMu.Lock()
	o, ok := fd.gem.lookup(req.BoHandle)
	fd.gemMu.Unlock()
	if !ok {
		return linuxerr.ENOENT
	}

	req.ResHandle = o.resID
	req.Size = uint32(o.size)
	req.BlobMem = o.blobMem
	_, _ = binary.Encode(arg, binary.LittleEndian, &req)
	return nil
}
