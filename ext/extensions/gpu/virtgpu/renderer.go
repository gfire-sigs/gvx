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
	"errors"

	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/log"
)

// Renderer is the host renderer process of one sandbox, as the device sees it.
// Methods are safe for concurrent use. After the renderer is lost, every method
// returns an error that wraps gpuproto.ErrRendererLost.
type Renderer interface {
	// Capset returns the capset data of id at version, as cached during the handshake. It does no I/O. ok is false for an unknown id or a version above the maximum.
	Capset(id, version uint32) (data []byte, ok bool)
	// CreateContext creates ctxID with capsetID and waits for the reply. name is the guest debug name (at most 64 bytes; may be empty).
	CreateContext(ctx stdcontext.Context, ctxID, capsetID uint32, name string) error
	// DestroyContext sends CTX_DESTROY and returns without waiting for the reply.
	DestroyContext(ctxID uint32) error
	// CreateBlob creates and attaches a blob, then waits for the reply. On success the caller owns Blob.Shm.
	CreateBlob(ctx stdcontext.Context, req gpuproto.BlobCreate) (gpuproto.Blob, error)
	// UnrefResource sends RES_UNREF (detach, then unref) and returns without waiting for the reply.
	UnrefResource(ctxID, resID uint32) error
	// Submit sends cmd with an optional fence and returns once the request is written. It does not wait for the reply. A write that blocks past the request timeout loses the renderer.
	Submit(ctxID uint32, cmd []byte, fence *gpuproto.Fence) error
	// SetEventSink installs the event receiver. Call it once, before the first CreateContext.
	SetEventSink(sink gpuproto.EventSink)
	// Mode returns the command stream that the renderer serves. It never changes.
	Mode() gpuproto.Mode
	// CreateResource creates a virgl resource with a shared-memory backing,
	// attaches it to req.CtxID, and waits for the reply. On success the caller
	// owns Blob.Shm.
	CreateResource(ctx stdcontext.Context, req gpuproto.ResourceCreate) (gpuproto.Blob, error)
	// Transfer runs one TRANSFER and waits until the copy is complete.
	Transfer(ctx stdcontext.Context, req gpuproto.Transfer) error
}

// callRenderer runs call on a new goroutine and blocks the task until call
// returns. When the task is interrupted first, callRenderer cancels the
// context of call and waits for call to return. The client promises to return
// promptly after a cancel. A call that succeeds although it was cancelled
// keeps its result, because the client does not undo a result that it
// reported.
func callRenderer(ctx context.Context, call func(stdcontext.Context) error) error {
	cctx, cancel := stdcontext.WithCancel(stdcontext.Background())
	defer cancel()
	done := make(chan struct{})
	var err error
	go func() {
		err = call(cctx)
		close(done)
	}()
	if ctx.Block(done) != nil {
		cancel()
		<-done
	}
	return rendererErrno(err)
}

// rendererErrno maps an error of a Renderer method to the errno of the guest.
func rendererErrno(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gpuproto.ErrRendererLost) {
		return linuxerr.EIO
	}
	var se *gpuproto.StatusError
	if errors.As(err, &se) {
		switch se.Status {
		case gpuproto.StatusInvalid:
			return linuxerr.EINVAL
		case gpuproto.StatusNoMemory:
			return linuxerr.ENOMEM
		case gpuproto.StatusNoSpace:
			return linuxerr.ENOSPC
		case gpuproto.StatusIO:
			return linuxerr.EIO
		case gpuproto.StatusNotSupported:
			return linuxerr.EOPNOTSUPP
		case gpuproto.StatusExists:
			return linuxerr.EEXIST
		default:
			return linuxerr.EIO
		}
	}
	if errors.Is(err, stdcontext.Canceled) {
		return linuxerr.ERESTARTSYS
	}
	log.Warningf("virtgpu: renderer call: %v", err)
	return linuxerr.EIO
}
