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
	"fmt"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func putContextInit(t *testing.T, mem *guestMem, structAddr, paramsAddr hostarch.Addr, params []virtgpuContextSetParam) {
	t.Helper()
	for i, p := range params {
		mem.put(t, paramsAddr+hostarch.Addr(i*16), p)
	}
	mem.put(t, structAddr, virtgpuContextInit{
		NumParams:    uint32(len(params)),
		CtxSetParams: uint64(paramsAddr),
	})
}

func mesaVenusParams() []virtgpuContextSetParam {
	return []virtgpuContextSetParam{
		{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
		{Param: virtgpuContextParamNumRings, Value: gpuproto.MaxRings},
		{Param: virtgpuContextParamPollRingsMask, Value: 0},
	}
}

func TestContextInitVenus(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		paramsAddr = hostarch.Addr(0x2000)
	)
	putContextInit(t, mem, structAddr, paramsAddr, mesaVenusParams())
	if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); err != nil {
		t.Fatalf("CONTEXT_INIT: %v", err)
	}

	calls := fake.createdCalls()
	if len(calls) != 1 {
		t.Fatalf("CreateContext calls = %d, want 1", len(calls))
	}
	if calls[0].ctxID == 0 || calls[0].capsetID != virtgpuCapsetVenus || calls[0].name != "" {
		t.Errorf("CreateContext call = %+v, want nonzero ctxID, capset 4, empty name", calls[0])
	}

	// Second CONTEXT_INIT returns EEXIST without calling the renderer again.
	if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); !linuxerr.Equals(linuxerr.EEXIST, err) {
		t.Fatalf("second CONTEXT_INIT: got %v, want EEXIST", err)
	}
	if got := len(fake.createdCalls()); got != 1 {
		t.Errorf("CreateContext calls after EEXIST = %d, want 1", got)
	}
}

func TestContextInitRejectsParameters(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		paramsAddr = hostarch.Addr(0x2000)
	)

	cases := []struct {
		name   string
		params []virtgpuContextSetParam
	}{
		{"0 params", nil},
		{
			"5 params",
			[]virtgpuContextSetParam{
				{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
				{Param: virtgpuContextParamNumRings, Value: 1},
				{Param: virtgpuContextParamPollRingsMask, Value: 0},
				{Param: virtgpuContextParamDebugName, Value: 0},
				{Param: virtgpuContextParamNumRings, Value: 2},
			},
		},
		{"capset 1", []virtgpuContextSetParam{{Param: virtgpuContextParamCapsetID, Value: 1}}},
		{"capset 64", []virtgpuContextSetParam{{Param: virtgpuContextParamCapsetID, Value: 64}}},
		{"no capset", []virtgpuContextSetParam{{Param: virtgpuContextParamNumRings, Value: 1}}},
		{
			"capset twice",
			[]virtgpuContextSetParam{
				{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
				{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
			},
		},
		{
			"rings 65",
			[]virtgpuContextSetParam{
				{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
				{Param: virtgpuContextParamNumRings, Value: gpuproto.MaxRings + 1},
			},
		},
		{
			"rings twice",
			[]virtgpuContextSetParam{
				{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
				{Param: virtgpuContextParamNumRings, Value: 1},
				{Param: virtgpuContextParamNumRings, Value: 2},
			},
		},
		{
			"poll mask 1",
			[]virtgpuContextSetParam{
				{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
				{Param: virtgpuContextParamPollRingsMask, Value: 1},
			},
		},
		{
			"unknown param 5",
			[]virtgpuContextSetParam{
				{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
				{Param: 5, Value: 0},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			putContextInit(t, mem, structAddr, paramsAddr, tc.params)
			err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr)
			if !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Errorf("CONTEXT_INIT(%s): got %v, want EINVAL", tc.name, err)
			}
			if got := len(fake.createdCalls()); got != 0 {
				t.Errorf("CONTEXT_INIT(%s): renderer saw %d calls, want 0", tc.name, got)
			}
		})
	}

	t.Run("non-zero pad", func(t *testing.T) {
		putContextInit(t, mem, structAddr, paramsAddr, mesaVenusParams())
		mem.put(t, structAddr, virtgpuContextInit{
			NumParams:    uint32(len(mesaVenusParams())),
			Pad:          1,
			CtxSetParams: uint64(paramsAddr),
		})
		if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); !linuxerr.Equals(linuxerr.EINVAL, err) {
			t.Errorf("CONTEXT_INIT(pad=1): got %v, want EINVAL", err)
		}
		if got := len(fake.createdCalls()); got != 0 {
			t.Errorf("CONTEXT_INIT(pad=1): renderer saw %d calls, want 0", got)
		}
	})
}

func TestContextInitDebugName(t *testing.T) {
	const (
		structAddr = hostarch.Addr(0x1000)
		paramsAddr = hostarch.Addr(0x2000)
		nameAddr   = hostarch.Addr(0x3000)
	)

	t.Run("short name", func(t *testing.T) {
		fake := newFakeRenderer()
		node := newTestNode(t, fake)
		fd := node.open(t)
		defer fd.DecRef(node.ctx)

		mem := newGuestMem()
		mem.writeBytes(nameAddr, append([]byte("chromium"), 0))
		params := []virtgpuContextSetParam{
			{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
			{Param: virtgpuContextParamDebugName, Value: uint64(nameAddr)},
		}
		putContextInit(t, mem, structAddr, paramsAddr, params)
		if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); err != nil {
			t.Fatalf("CONTEXT_INIT: %v", err)
		}
		calls := fake.createdCalls()
		if len(calls) != 1 || calls[0].name != "chromium" {
			t.Errorf("CreateContext calls = %+v, want name %q", calls, "chromium")
		}
	})

	t.Run("unterminated 100-byte name truncates to 63", func(t *testing.T) {
		fake := newFakeRenderer()
		node := newTestNode(t, fake)
		fd := node.open(t)
		defer fd.DecRef(node.ctx)

		mem := newGuestMem()
		longName := strings.Repeat("a", 100)
		mem.writeBytes(nameAddr, []byte(longName))
		params := []virtgpuContextSetParam{
			{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
			{Param: virtgpuContextParamDebugName, Value: uint64(nameAddr)},
		}
		putContextInit(t, mem, structAddr, paramsAddr, params)
		if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); err != nil {
			t.Fatalf("CONTEXT_INIT: %v", err)
		}
		calls := fake.createdCalls()
		want := longName[:gpuproto.MaxContextNameBytes-1]
		if len(calls) != 1 || calls[0].name != want {
			t.Errorf("CreateContext name len = %d, want %d", len(calls[0].name), len(want))
		}
	})

	t.Run("63-byte name at end of guest memory does not read byte 64", func(t *testing.T) {
		fake := newFakeRenderer()
		node := newTestNode(t, fake)
		fd := node.open(t)
		defer fd.DecRef(node.ctx)

		mem := newGuestMem()
		const maxName = gpuproto.MaxContextNameBytes - 1
		endAddr := hostarch.Addr(guestMemSize - maxName)
		want := strings.Repeat("b", maxName)
		mem.writeBytes(endAddr, []byte(want))
		params := []virtgpuContextSetParam{
			{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
			{Param: virtgpuContextParamDebugName, Value: uint64(endAddr)},
		}
		putContextInit(t, mem, structAddr, paramsAddr, params)
		if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); err != nil {
			t.Fatalf("CONTEXT_INIT at end of guest memory: %v", err)
		}
		calls := fake.createdCalls()
		if len(calls) != 1 || calls[0].name != want {
			t.Errorf("CreateContext name = %q (len %d), want %q", calls[0].name, len(calls[0].name), want)
		}
	})

	t.Run("bad name pointer returns EFAULT", func(t *testing.T) {
		fake := newFakeRenderer()
		node := newTestNode(t, fake)
		fd := node.open(t)
		defer fd.DecRef(node.ctx)

		mem := newGuestMem()
		params := []virtgpuContextSetParam{
			{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
			{Param: virtgpuContextParamDebugName, Value: uint64(badGuestAddr)},
		}
		putContextInit(t, mem, structAddr, paramsAddr, params)
		if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); !linuxerr.Equals(linuxerr.EFAULT, err) {
			t.Errorf("CONTEXT_INIT(bad name ptr): got %v, want EFAULT", err)
		}
	})
}

func TestContextInitMapsRendererErrors(t *testing.T) {
	const (
		structAddr = hostarch.Addr(0x1000)
		paramsAddr = hostarch.Addr(0x2000)
	)

	cases := []struct {
		name        string
		rendererErr error
		wantErrno   error
	}{
		{"StatusNoMemory", &gpuproto.StatusError{Op: gpuproto.OpCtxCreate, Status: gpuproto.StatusNoMemory}, linuxerr.ENOMEM},
		{"StatusExists", &gpuproto.StatusError{Op: gpuproto.OpCtxCreate, Status: gpuproto.StatusExists}, linuxerr.EEXIST},
		{"ErrRendererLost", fmt.Errorf("write failed: %w", gpuproto.ErrRendererLost), linuxerr.EIO},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeRenderer()
			fake.setCreateErr(tc.rendererErr)
			node := newTestNode(t, fake)
			fd := node.open(t)
			defer fd.DecRef(node.ctx)

			mem := newGuestMem()
			putContextInit(t, mem, structAddr, paramsAddr, mesaVenusParams())
			if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); !errors.Is(err, tc.wantErrno) {
				t.Fatalf("CONTEXT_INIT(%s): got %v, want %v", tc.name, err, tc.wantErrno)
			}

			// Retry with a working renderer succeeds with a new context ID (2).
			fake.setCreateErr(nil)
			if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); err != nil {
				t.Fatalf("CONTEXT_INIT retry after %s: %v", tc.name, err)
			}
			calls := fake.createdCalls()
			if len(calls) != 1 || calls[0].ctxID != 2 {
				t.Errorf("retry CreateContext calls = %+v, want single call with ctxID 2", calls)
			}
		})
	}
}

func TestContextInitInterruptedRestarts(t *testing.T) {
	fake := newFakeRenderer()
	fake.createGate = make(chan struct{})
	fake.createEntered = make(chan struct{}, 1)
	node := newTestNode(t, fake)
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		paramsAddr = hostarch.Addr(0x2000)
	)
	putContextInit(t, mem, structAddr, paramsAddr, mesaVenusParams())

	ictx := newTestTaskCtx(t, node.ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- node.ioctlWithCtx(ictx, fd, cmdVirtgpuContextInit, mem, structAddr)
	}()

	<-fake.createEntered
	ictx.Interrupt()

	err := <-errCh
	if !linuxerr.Equals(linuxerr.ERESTARTSYS, err) {
		t.Fatalf("interrupted CONTEXT_INIT: got %v, want ERESTARTSYS", err)
	}
	if !fake.wasCanceled() {
		t.Errorf("renderer CreateContext did not observe context cancellation")
	}

	node.dev.mu.Lock()
	remaining := len(node.dev.contexts)
	node.dev.mu.Unlock()
	if remaining != 0 {
		t.Errorf("Device.contexts len after cancel = %d, want 0", remaining)
	}

	// Subsequent CONTEXT_INIT succeeds with a larger context ID.
	close(fake.createGate)
	if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); err != nil {
		t.Fatalf("CONTEXT_INIT after interrupt: %v", err)
	}
	calls := fake.createdCalls()
	if len(calls) != 1 || calls[0].ctxID <= 1 {
		t.Errorf("CreateContext calls = %+v, want ctxID > 1", calls)
	}
}

func TestContextLostIsIdempotent(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		paramsAddr = hostarch.Addr(0x2000)
		valAddr    = hostarch.Addr(0x3000)
	)
	putContextInit(t, mem, structAddr, paramsAddr, mesaVenusParams())
	if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); err != nil {
		t.Fatalf("CONTEXT_INIT: %v", err)
	}
	ctxID := fake.createdCalls()[0].ctxID

	fake.emitContextLost(ctxID)
	fake.emitContextLost(ctxID)
	fake.emitContextLost(9999)

	// The file still answers GETPARAM.
	mem.put(t, structAddr, virtgpuGetparam{Param: virtgpuParam3DFeatures, Value: uint64(valAddr)})
	if err := node.ioctl(fd, cmdVirtgpuGetparam, mem, structAddr); err != nil {
		t.Fatalf("GETPARAM after ContextLost: %v", err)
	}
}

func TestContextDestroyedOnClose(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)

	// Closing a file without CONTEXT_INIT sends no DestroyContext.
	fdNoCtx := node.open(t)
	fdNoCtx.DecRef(node.ctx)
	if got := fake.destroyedIDs(); len(got) != 0 {
		t.Fatalf("DestroyContext calls without CONTEXT_INIT = %v, want empty", got)
	}

	// Closing a file with a context sends DestroyContext(id) once.
	fd := node.open(t)
	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		paramsAddr = hostarch.Addr(0x2000)
	)
	putContextInit(t, mem, structAddr, paramsAddr, mesaVenusParams())
	if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); err != nil {
		fd.DecRef(node.ctx)
		t.Fatalf("CONTEXT_INIT: %v", err)
	}
	ctxID := fake.createdCalls()[0].ctxID

	fd.DecRef(node.ctx)
	got := fake.destroyedIDs()
	if len(got) != 1 || got[0] != ctxID {
		t.Errorf("DestroyContext calls = %v, want [%d]", got, ctxID)
	}
}

func TestContextIDsArePerDevice(t *testing.T) {
	fakeA := newFakeRenderer()
	fakeB := newFakeRenderer()
	nodeA := newTestNode(t, fakeA)
	nodeB := newTestNode(t, fakeB)

	initOn := func(n *testNode) *vfs.FileDescription {
		t.Helper()
		fd := n.open(t)
		mem := newGuestMem()
		putContextInit(t, mem, 0x1000, 0x2000, mesaVenusParams())
		if err := n.ioctl(fd, cmdVirtgpuContextInit, mem, 0x1000); err != nil {
			fd.DecRef(n.ctx)
			t.Fatalf("CONTEXT_INIT: %v", err)
		}
		return fd
	}

	fdA1 := initOn(nodeA)
	defer fdA1.DecRef(nodeA.ctx)
	fdA2 := initOn(nodeA)
	defer fdA2.DecRef(nodeA.ctx)
	fdB1 := initOn(nodeB)
	defer fdB1.DecRef(nodeB.ctx)

	callsA := fakeA.createdCalls()
	callsB := fakeB.createdCalls()
	if len(callsA) != 2 || callsA[0].ctxID != 1 || callsA[1].ctxID != 2 {
		t.Errorf("node A ctxIDs = %+v, want 1 and 2", callsA)
	}
	if len(callsB) != 1 || callsB[0].ctxID != 1 {
		t.Errorf("node B ctxIDs = %+v, want 1", callsB)
	}
}

func TestContextInitAfterRendererLost(t *testing.T) {
	const (
		structAddr = hostarch.Addr(0x1000)
		paramsAddr = hostarch.Addr(0x2000)
	)

	t.Run("emitRendererLost before CONTEXT_INIT returns EIO", func(t *testing.T) {
		fake := newFakeRenderer()
		node := newTestNode(t, fake)
		fd := node.open(t)
		defer fd.DecRef(node.ctx)

		fake.emitRendererLost(errors.New("renderer crashed"))

		mem := newGuestMem()
		putContextInit(t, mem, structAddr, paramsAddr, mesaVenusParams())
		if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); !linuxerr.Equals(linuxerr.EIO, err) {
			t.Fatalf("CONTEXT_INIT after RendererLost: got %v, want EIO", err)
		}
		if got := len(fake.createdCalls()); got != 0 {
			t.Errorf("CreateContext calls = %d, want 0", got)
		}
		// fakeRenderer stays sticky-lost for all renderer calls.
		if err := fake.CreateContext(t.Context(), 1, virtgpuCapsetVenus, ""); !errors.Is(err, gpuproto.ErrRendererLost) {
			t.Errorf("fake.CreateContext after loss = %v, want ErrRendererLost", err)
		}
		if _, err := fake.CreateBlob(t.Context(), gpuproto.BlobCreate{CtxID: 1, ResID: 1, BlobMem: virtgpuBlobMemHost3D, Size: 0x1000}); !errors.Is(err, gpuproto.ErrRendererLost) {
			t.Errorf("fake.CreateBlob after loss = %v, want ErrRendererLost", err)
		}
		if err := fake.Submit(1, nil, nil); !errors.Is(err, gpuproto.ErrRendererLost) {
			t.Errorf("fake.Submit after loss = %v, want ErrRendererLost", err)
		}
		if err := fake.UnrefResource(1, 1); !errors.Is(err, gpuproto.ErrRendererLost) {
			t.Errorf("fake.UnrefResource after loss = %v, want ErrRendererLost", err)
		}
		if err := fake.DestroyContext(1); !errors.Is(err, gpuproto.ErrRendererLost) {
			t.Errorf("fake.DestroyContext after loss = %v, want ErrRendererLost", err)
		}
	})

	t.Run("emitRendererLost during CONTEXT_INIT returns EIO", func(t *testing.T) {
		fake := newFakeRenderer()
		fake.createGate = make(chan struct{})
		fake.createEntered = make(chan struct{}, 1)
		node := newTestNode(t, fake)
		fd := node.open(t)
		defer fd.DecRef(node.ctx)

		mem := newGuestMem()
		putContextInit(t, mem, structAddr, paramsAddr, mesaVenusParams())

		errCh := make(chan error, 1)
		go func() {
			errCh <- node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr)
		}()

		<-fake.createEntered
		fake.emitRendererLost(errors.New("renderer crashed mid-init"))
		close(fake.createGate)

		if err := <-errCh; !linuxerr.Equals(linuxerr.EIO, err) {
			t.Fatalf("CONTEXT_INIT during RendererLost: got %v, want EIO", err)
		}
		if got := len(fake.createdCalls()); got != 0 {
			t.Errorf("CreateContext calls = %d, want 0", got)
		}
		// Subsequent CONTEXT_INIT also fails with EIO, not EEXIST.
		if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); !linuxerr.Equals(linuxerr.EIO, err) {
			t.Fatalf("second CONTEXT_INIT after RendererLost: got %v, want EIO", err)
		}
	})
}
