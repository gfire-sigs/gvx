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

package gpuproto

import (
	"errors"
	"fmt"

	"z.gfire.dev/gvx/pkg/fd"
)

// ErrRendererLost identifies a dead, hung, or protocol-breaking renderer
// process; every client error wraps it after renderer loss. The device maps
// it to EIO.
var ErrRendererLost = errors.New("gpuproto: GPU renderer lost")

// StatusError reports a request that the renderer refused with a non-zero
// status.
type StatusError struct {
	Op     Op
	Status Status
}

// Error returns "gpuproto: renderer refused <OP>: <ERRNO>".
func (e *StatusError) Error() string {
	return fmt.Sprintf("gpuproto: renderer refused %s: %s", e.Op, e.Status)
}

// Errno returns the Linux errno number of e.Status as a positive value (22
// for StatusInvalid).
func (e *StatusError) Errno() uint32 {
	return e.Status.Errno()
}

// BlobCreate is the input of BLOB_CREATE. BlobMem is BlobMemHost3D on day
// one. BlobMem and BlobFlags carry the virtio-gpu uAPI values unchanged.
type BlobCreate struct {
	CtxID, ResID       uint32
	BlobMem, BlobFlags uint32
	BlobID             uint64
	// Size is the guest-requested size in bytes.
	Size uint64
}

const knownBlobFlags = BlobFlagMappable | BlobFlagShareable | BlobFlagCrossDevice

// Validate rejects a request that the renderer would refuse: zero IDs, a
// BlobMem other than BlobMemHost3D, unknown flag bits, and a Size of 0 or
// above MaxBlobBytes. The error is a *StatusError with StatusInvalid.
func (b BlobCreate) Validate() error {
	if b.CtxID == 0 ||
		b.ResID == 0 ||
		b.BlobMem != BlobMemHost3D ||
		b.BlobFlags&^knownBlobFlags != 0 ||
		b.Size == 0 ||
		b.Size > MaxBlobBytes {
		return &StatusError{Op: OpBlobCreate, Status: StatusInvalid}
	}
	return nil
}

// Blob is the result of BLOB_CREATE. The caller owns Shm and must Close it.
// Shm is nil and HostSize is 0 when the blob is not mappable.
type Blob struct {
	// Shm is the POSIX shared-memory descriptor received with SCM_RIGHTS,
	// opened read-write, with close-on-exec set.
	Shm *fd.HostHandle
	// HostSize is the size that the renderer reported. It is a multiple of
	// HostBlobAlign and at least the requested size. The device verifies it
	// with fstat.
	HostSize uint64
}

// Fence asks the renderer to signal FENCE_DONE after the commands of the
// same SUBMIT retire on ring RingIdx.
type Fence struct {
	RingIdx uint32
	// The device allocates ID. It is never 0 and unique in a sandbox.
	ID uint64
}

// Validate rejects ID 0 and RingIdx >= MaxRings with a *StatusError that
// has Op OpSubmit and StatusInvalid.
func (f Fence) Validate() error {
	if f.ID == 0 || f.RingIdx >= MaxRings {
		return &StatusError{Op: OpSubmit, Status: StatusInvalid}
	}
	return nil
}

// EventSink receives renderer events. A client calls it from one goroutine
// in stream order, except for the case that SetEventSink documents. An
// implementation must not block and must not call a renderer method that
// waits for a reply.
type EventSink interface {
	// FenceDone reports that the fence (ctxID, ringIdx, fenceID) retired.
	FenceDone(ctxID, ringIdx uint32, fenceID uint64)
	// ContextLost reports that ctxID can no longer run commands. It can
	// arrive more than once for one context; an implementation ignores a
	// repeat.
	ContextLost(ctxID uint32)
	// The client calls RendererLost once. Before the call, the client fails
	// every pending call with ErrRendererLost. After it, the client delivers
	// no event.
	RendererLost(err error)
}
