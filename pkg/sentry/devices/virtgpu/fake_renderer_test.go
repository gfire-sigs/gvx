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
	stdcontext "context"
	"fmt"
	"slices"
	"sync"

	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

type capsetKey struct {
	id      uint32
	version uint32
}

type createCall struct {
	ctxID    uint32
	capsetID uint32
	name     string
}

type unrefCall struct {
	ctxID uint32
	resID uint32
}

type submitCall struct {
	ctxID uint32
	cmd   []byte
	fence *gpuproto.Fence
}

type fakeOp struct {
	kind  string // "Submit", "CreateBlob", "UnrefResource", "DestroyContext"
	ctxID uint32
	resID uint32
	cmd   []byte
}

type fakeRenderer struct {
	mu sync.Mutex

	capsets        map[capsetKey][]byte
	contexts       map[uint32]createCall
	created        []createCall
	destroyed      []uint32
	createErr      error
	createGate     chan struct{}
	createEntered  chan struct{}
	createCanceled bool

	blobsCreated   []gpuproto.BlobCreate
	blobViews      map[uint32][]byte
	blobErr        error
	shortShm       bool
	unexpectedShm  bool
	nilMappableShm bool
	blobGate       chan struct{}
	blobEntered    chan struct{}
	blobCanceled   bool

	unrefed   []unrefCall
	submits   []submitCall
	submitErr error
	ops       []fakeOp

	sink           gpuproto.EventSink
	sinkSet        bool
	lostBeforeSink bool
	lostErr        error
	lost           bool
}

var _ Renderer = (*fakeRenderer)(nil)

func newFakeRenderer() *fakeRenderer {
	capData := make([]byte, 160)
	for i := range capData {
		capData[i] = byte(i + 1)
	}
	return &fakeRenderer{
		capsets: map[capsetKey][]byte{
			{id: virtgpuCapsetVenus, version: 0}: capData,
		},
		contexts:  make(map[uint32]createCall),
		blobViews: make(map[uint32][]byte),
	}
}

func (f *fakeRenderer) cleanup() {
	f.mu.Lock()
	views := f.blobViews
	f.blobViews = nil
	f.mu.Unlock()
	for _, v := range views {
		unmapFakeShm(v)
	}
}

func (f *fakeRenderer) Capset(id, version uint32) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.capsets[capsetKey{id: id, version: version}]
	if !ok {
		return nil, false
	}
	return slices.Clone(data), true
}

func (f *fakeRenderer) CreateContext(ctx stdcontext.Context, ctxID, capsetID uint32, name string) error {
	f.mu.Lock()
	gate := f.createGate
	entered := f.createEntered
	f.mu.Unlock()

	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}

	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			f.mu.Lock()
			f.createCanceled = true
			f.mu.Unlock()
			return ctx.Err()
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lost {
		return fmt.Errorf("fakeRenderer: %w", gpuproto.ErrRendererLost)
	}
	if f.createErr != nil {
		return f.createErr
	}
	call := createCall{ctxID: ctxID, capsetID: capsetID, name: name}
	f.created = append(f.created, call)
	f.contexts[ctxID] = call
	return nil
}

func (f *fakeRenderer) DestroyContext(ctxID uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyed = append(f.destroyed, ctxID)
	f.ops = append(f.ops, fakeOp{kind: "DestroyContext", ctxID: ctxID})
	delete(f.contexts, ctxID)
	if f.lost {
		return fmt.Errorf("fakeRenderer: %w", gpuproto.ErrRendererLost)
	}
	return nil
}

func (f *fakeRenderer) CreateBlob(ctx stdcontext.Context, req gpuproto.BlobCreate) (gpuproto.Blob, error) {
	f.mu.Lock()
	gate := f.blobGate
	entered := f.blobEntered
	f.mu.Unlock()

	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}

	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			f.mu.Lock()
			f.blobCanceled = true
			f.mu.Unlock()
			return gpuproto.Blob{}, ctx.Err()
		}
	}

	f.mu.Lock()
	if f.lost {
		f.mu.Unlock()
		return gpuproto.Blob{}, fmt.Errorf("fakeRenderer: %w", gpuproto.ErrRendererLost)
	}
	if f.blobErr != nil {
		err := f.blobErr
		f.mu.Unlock()
		return gpuproto.Blob{}, err
	}
	f.blobsCreated = append(f.blobsCreated, req)
	f.ops = append(f.ops, fakeOp{kind: "CreateBlob", ctxID: req.CtxID, resID: req.ResID})
	short := f.shortShm
	unexpected := f.unexpectedShm
	nilMappable := f.nilMappableShm
	f.mu.Unlock()

	mappable := req.BlobFlags&virtgpuBlobFlagUseMappable != 0
	if !mappable {
		if unexpected {
			h, view, err := allocFakeShm(blobAlignment)
			if err != nil {
				return gpuproto.Blob{}, err
			}
			f.mu.Lock()
			if f.blobViews == nil {
				f.blobViews = make(map[uint32][]byte)
			}
			f.blobViews[req.ResID] = view
			f.mu.Unlock()
			return gpuproto.Blob{Shm: h, HostSize: blobAlignment}, nil
		}
		return gpuproto.Blob{}, nil
	}
	if nilMappable {
		return gpuproto.Blob{}, nil
	}

	hostSize := ((req.Size + blobAlignment - 1) / blobAlignment) * blobAlignment
	allocSize := hostSize
	if short {
		allocSize = hostSize / 2
	}
	h, view, err := allocFakeShm(int64(allocSize))
	if err != nil {
		return gpuproto.Blob{}, err
	}
	f.mu.Lock()
	if f.blobViews == nil {
		f.blobViews = make(map[uint32][]byte)
	}
	f.blobViews[req.ResID] = view
	f.mu.Unlock()
	return gpuproto.Blob{Shm: h, HostSize: allocSize}, nil
}

func (f *fakeRenderer) UnrefResource(ctxID, resID uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unrefed = append(f.unrefed, unrefCall{ctxID: ctxID, resID: resID})
	f.ops = append(f.ops, fakeOp{kind: "UnrefResource", ctxID: ctxID, resID: resID})
	if f.lost {
		return fmt.Errorf("fakeRenderer: %w", gpuproto.ErrRendererLost)
	}
	return nil
}

func (f *fakeRenderer) Submit(ctxID uint32, cmd []byte, fence *gpuproto.Fence) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lost {
		return fmt.Errorf("fakeRenderer: %w", gpuproto.ErrRendererLost)
	}
	if f.submitErr != nil {
		return f.submitErr
	}
	var fenceCopy *gpuproto.Fence
	if fence != nil {
		cp := *fence
		fenceCopy = &cp
	}
	cmdCopy := slices.Clone(cmd)
	f.submits = append(f.submits, submitCall{
		ctxID: ctxID,
		cmd:   cmdCopy,
		fence: fenceCopy,
	})
	f.ops = append(f.ops, fakeOp{kind: "Submit", ctxID: ctxID, cmd: cmdCopy})
	return nil
}

func (f *fakeRenderer) SetEventSink(sink gpuproto.EventSink) {
	f.mu.Lock()
	if f.sinkSet {
		f.mu.Unlock()
		panic("fakeRenderer: SetEventSink called twice")
	}
	f.sink = sink
	f.sinkSet = true
	lost := f.lostBeforeSink
	lostErr := f.lostErr
	if lost {
		f.lost = true
	}
	f.mu.Unlock()

	if lost {
		sink.RendererLost(lostErr)
	}
}

func (f *fakeRenderer) emitFenceDone(ctxID, ring uint32, id uint64) {
	f.mu.Lock()
	sink := f.sink
	f.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		sink.FenceDone(ctxID, ring, id)
	}()
	<-done
}

func (f *fakeRenderer) emitContextLost(id uint32) {
	f.mu.Lock()
	sink := f.sink
	f.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		sink.ContextLost(id)
	}()
	<-done
}

func (f *fakeRenderer) emitRendererLost(err error) {
	f.mu.Lock()
	f.lost = true
	sink := f.sink
	f.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		sink.RendererLost(err)
	}()
	<-done
}

func (f *fakeRenderer) blobMemory(resID uint32) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blobViews[resID]
}

func (f *fakeRenderer) createdCalls() []createCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.created)
}

func (f *fakeRenderer) destroyedIDs() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.destroyed)
}

func (f *fakeRenderer) blobCreateCalls() []gpuproto.BlobCreate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.blobsCreated)
}

func (f *fakeRenderer) unrefCalls() []unrefCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.unrefed)
}

func (f *fakeRenderer) submitCalls() []submitCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.submits)
}

func (f *fakeRenderer) opLog() []fakeOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ops)
}

func (f *fakeRenderer) setCreateErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createErr = err
}

func (f *fakeRenderer) setBlobErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobErr = err
}

func (f *fakeRenderer) setSubmitErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submitErr = err
}

func (f *fakeRenderer) wasCanceled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createCanceled
}

func (f *fakeRenderer) wasBlobCanceled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blobCanceled
}

func (f *fakeRenderer) hasSink() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sinkSet
}
