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
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// Magic is the first field of every header ("GPU1" in byte order).
	Magic uint32 = 0x31555047
	// Version is the protocol version that HELLO negotiates. Both sides
	// require an exact match.
	Version uint32 = 2
	// HeaderSize is the encoded size of Header in bytes.
	HeaderSize = 24
	// SocketFD is the descriptor number of the socket in the renderer.
	SocketFD = 3
)

const (
	// MaxCapsets is the largest capset count in a HELLO reply.
	MaxCapsets = 8
	// MaxCapsetVersion is the largest max_version that a capset can report.
	MaxCapsetVersion = 4
	// MaxCapsetBytes is the largest capset size.
	MaxCapsetBytes = 4096
	// MaxContextNameBytes is the largest context debug name.
	MaxContextNameBytes = 64
	// MaxSubmitBytes is the largest command buffer of one SUBMIT.
	MaxSubmitBytes = 16 << 20
	// MaxRings is the ring count of a venus context; a ring index is below it.
	MaxRings = 64
	// MaxBlobBytes is the largest size of one blob.
	MaxBlobBytes = 1 << 30
	// HostBlobAlign is the host page size. The host size of a mappable blob
	// is a multiple of it.
	HostBlobAlign = 0x4000
	// MaxReplyPayload is the largest payload of any reply or event.
	MaxReplyPayload = 64 << 10
)

const (
	// CapsetVirgl is the virgl v1 capset ID (VIRTGPU_DRM_CAPSET_VIRGL).
	CapsetVirgl = 1
	// CapsetVirgl2 is the virgl v2 capset ID (VIRTGPU_DRM_CAPSET_VIRGL2).
	CapsetVirgl2 = 2
	// CapsetVenus is the venus capset ID (virtio-gpu uAPI VIRTGPU_CAPSET_VENUS).
	CapsetVenus = 4
	// BlobMemHost3D is VIRTGPU_BLOB_MEM_HOST3D, the only blob memory type that
	// the renderer accepts.
	BlobMemHost3D = 2
	// Blob flags are the virtio-gpu uAPI values VIRTGPU_BLOB_FLAG_USE_*.
	BlobFlagMappable    = 1
	BlobFlagShareable   = 2
	BlobFlagCrossDevice = 4
	// FDTypeShm is VIRGL_RENDERER_BLOB_FD_TYPE_SHM, the descriptor type that
	// BLOB_CREATE and RES_CREATE replies carry.
	FDTypeShm = 3
	// SubmitFlagFence marks a SUBMIT that carries a fence.
	SubmitFlagFence = 1
	// TransferToHost copies from the attached backing to the vrend resource.
	TransferToHost = 1
	// TransferFromHost copies from the vrend resource to the attached backing.
	TransferFromHost = 2
)

// Mode is the command stream that one renderer process serves. The renderer
// gets it on its command line (ArgMode) and confirms it in the HELLO reply.
type Mode uint32

const (
	// ModeVenus serves Vulkan through venus (capset CapsetVenus).
	ModeVenus Mode = 1
	// ModeVirgl serves OpenGL through vrend (capsets CapsetVirgl and CapsetVirgl2).
	ModeVirgl Mode = 2
)

// ModeNameVenus and ModeNameVirgl are the values of ArgMode.
const (
	ModeNameVenus = "venus"
	ModeNameVirgl = "virgl"
)

// String returns ModeNameVenus, ModeNameVirgl, or "MODE(n)".
func (m Mode) String() string {
	switch m {
	case ModeVenus:
		return ModeNameVenus
	case ModeVirgl:
		return ModeNameVirgl
	default:
		return fmt.Sprintf("MODE(%d)", m)
	}
}

// Valid reports whether m is ModeVenus or ModeVirgl.
func (m Mode) Valid() bool {
	return m == ModeVenus || m == ModeVirgl
}

// Capsets returns the capset IDs that mode m advertises, in increasing order:
// [CapsetVenus] for ModeVenus, [CapsetVirgl, CapsetVirgl2] for ModeVirgl, or
// nil otherwise.
func (m Mode) Capsets() []uint32 {
	switch m {
	case ModeVenus:
		return []uint32{CapsetVenus}
	case ModeVirgl:
		return []uint32{CapsetVirgl, CapsetVirgl2}
	default:
		return nil
	}
}

// PrimaryCapset returns CapsetVenus for ModeVenus and CapsetVirgl2 for
// ModeVirgl (the capset of an implicit context), or 0.
func (m Mode) PrimaryCapset() uint32 {
	switch m {
	case ModeVenus:
		return CapsetVenus
	case ModeVirgl:
		return CapsetVirgl2
	default:
		return 0
	}
}

const (
	// CtxLostSubmitFailed: virgl_renderer_submit_cmd failed for the context.
	CtxLostSubmitFailed = 1
	// CtxLostFenceFailed: virgl_renderer_context_create_fence failed.
	CtxLostFenceFailed = 2
)

// Renderer exit codes. The client names the code in the error that it
// returns when the renderer exits.
const (
	ExitOK          = 0 // end of file on SocketFD, or --selftest passed
	ExitUsage       = 2 // bad command line, or SocketFD is not a socket
	ExitInit        = 3 // KosmicKrisp, the Vulkan self-test, the OpenGL (CGL) probe, or virgl_renderer_init failed
	ExitConfine     = 4 // the Seatbelt profile or a resource limit could not be applied
	ExitProtocol    = 5 // the Sentry broke the protocol
	ExitSelftest    = 6 // --selftest found a failed check
	ExitMemoryLimit = 7 // the memory watchdog found phys_footprint above the threshold
)

// Command-line contract of the renderer.
const (
	ArgSelftest    = "--selftest"
	ArgStallFences = "--test-stall-fences"
	// ArgMemoryLimit prefixes the decimal byte count of the blob memory limit,
	// for example "--memory-limit=4294967296". The watchdog adds
	// WatchdogHeadroomBytes to it.
	ArgMemoryLimit = "--memory-limit="
	// ArgTestWatchdogBytes sets the watchdog threshold directly, in bytes. The
	// renderer accepts it only with EnvTestMode=1.
	ArgTestWatchdogBytes = "--test-watchdog-bytes="
	// ArgMode selects the command stream: ArgMode+ModeNameVenus or
	// ArgMode+ModeNameVirgl. Without it the renderer serves ModeVenus. The
	// renderer accepts it also with ArgSelftest.
	ArgMode = "--mode="
	// EnvTestMode must be "1" for the renderer to accept test arguments.
	EnvTestMode = "GVX_GPU_RENDERER_TEST"
	// WatchdogHeadroomBytes is the footprint that the renderer may use above
	// the blob memory limit: device-local Vulkan memory, pipelines, the driver.
	WatchdogHeadroomBytes = 512 << 20
	// WatchdogPeriodMillis is the sampling period of the watchdog.
	WatchdogPeriodMillis = 250
)

// Op is an operation code.
type Op uint16

const (
	OpHello       Op = 1  // request and reply
	OpGetCapset   Op = 2  // request and reply
	OpCtxCreate   Op = 3  // request and reply
	OpCtxDestroy  Op = 4  // request and reply
	OpBlobCreate  Op = 5  // request and reply (+1 descriptor for a mappable blob)
	OpResUnref    Op = 6  // request and reply
	OpSubmit      Op = 7  // request and reply
	OpFenceDone   Op = 8  // event
	OpCtxLost     Op = 9  // event
	OpTestConfine Op = 10 // request and reply; tests only (GVX_GPU_RENDERER_TEST=1)
	OpResCreate   Op = 11 // request and reply (+1 descriptor)
	OpTransfer    Op = 12 // request and reply
)

type opEntry struct {
	op   Op
	name string
}

var allOps = []opEntry{
	{OpHello, "HELLO"},
	{OpGetCapset, "GET_CAPSET"},
	{OpCtxCreate, "CTX_CREATE"},
	{OpCtxDestroy, "CTX_DESTROY"},
	{OpBlobCreate, "BLOB_CREATE"},
	{OpResUnref, "RES_UNREF"},
	{OpSubmit, "SUBMIT"},
	{OpFenceDone, "FENCE_DONE"},
	{OpCtxLost, "CTX_LOST"},
	{OpTestConfine, "TEST_CONFINE"},
	{OpResCreate, "RES_CREATE"},
	{OpTransfer, "TRANSFER"},
}

// String returns the protocol name of o, such as "BLOB_CREATE", or "OP(n)".
func (o Op) String() string {
	for _, entry := range allOps {
		if entry.op == o {
			return entry.name
		}
	}
	return fmt.Sprintf("OP(%d)", o)
}

// IsRequest reports whether o is a request operation: OpHello to OpSubmit,
// OpTestConfine, OpResCreate, or OpTransfer.
func (o Op) IsRequest() bool {
	return (o >= OpHello && o <= OpSubmit) || o == OpTestConfine || o == OpResCreate || o == OpTransfer
}

// IsEvent reports whether o is an event operation.
func (o Op) IsEvent() bool {
	return o == OpFenceDone || o == OpCtxLost
}

// Flags is the header flag word.
type Flags uint16

const (
	FlagReply Flags = 1 << 0
	FlagEvent Flags = 1 << 1
	// FlagFD marks a message with one descriptor in an SCM_RIGHTS message.
	FlagFD Flags = 1 << 2
)

const knownFlags = FlagReply | FlagEvent | FlagFD

// Status is the result of a request: 0 or a negative Linux errno number.
// The renderer sends only the values below. It never sends a host errno,
// because macOS errno numbers differ from Linux numbers.
type Status int32

const (
	StatusOK           Status = 0
	StatusIO           Status = -5  // EIO
	StatusNoMemory     Status = -12 // ENOMEM
	StatusExists       Status = -17 // EEXIST
	StatusInvalid      Status = -22 // EINVAL
	StatusNoSpace      Status = -28 // ENOSPC
	StatusNotSupported Status = -95 // EOPNOTSUPP
)

type statusEntry struct {
	status  Status
	cName   string
	errName string
}

var allStatuses = []statusEntry{
	{StatusOK, "OK", "OK"},
	{StatusIO, "IO", "EIO"},
	{StatusNoMemory, "NO_MEMORY", "ENOMEM"},
	{StatusExists, "EXISTS", "EEXIST"},
	{StatusInvalid, "INVALID", "EINVAL"},
	{StatusNoSpace, "NO_SPACE", "ENOSPC"},
	{StatusNotSupported, "NOT_SUPPORTED", "EOPNOTSUPP"},
}

// Known reports whether s is one of the Status constants.
func (s Status) Known() bool {
	for _, entry := range allStatuses {
		if entry.status == s {
			return true
		}
	}
	return false
}

// Errno returns the positive Linux errno number of s (22 for StatusInvalid).
// It returns 0 for StatusOK.
func (s Status) Errno() uint32 {
	if s >= 0 {
		return 0
	}
	return uint32(-int64(s))
}

// String returns the errno name of s, such as "EINVAL", "OK", or "STATUS(n)".
func (s Status) String() string {
	for _, entry := range allStatuses {
		if entry.status == s {
			return entry.errName
		}
	}
	return fmt.Sprintf("STATUS(%d)", s)
}

// Header is the fixed part of every message. Field order and widths are the
// wire layout; the c tags name the C fields.
type Header struct {
	Magic      uint32 `c:"magic"`
	Op         Op     `c:"op"`
	Flags      Flags  `c:"flags"`
	Seq        uint32 `c:"seq"`
	CtxID      uint32 `c:"ctx_id"`
	PayloadLen uint32 `c:"payload_len"`
	Status     Status `c:"status"`
}

// Direction names the sender of a message for ParseHeader.
type Direction uint8

const (
	// ToRenderer is a request from the Sentry.
	ToRenderer Direction = iota + 1
	// FromRenderer is a reply or an event from the renderer.
	FromRenderer
)

// ErrMalformed identifies protocol violations; every decode error for malformed
// bytes wraps ErrMalformed.
var ErrMalformed = errors.New("gpuproto: malformed message")

// AppendHeader appends the 24-byte encoding of h to dst. It does not set
// h.Magic; callers pass Magic.
func AppendHeader(dst []byte, h Header) []byte {
	out, err := binary.Append(dst, binary.LittleEndian, h)
	if err != nil {
		panic(err)
	}
	return out
}

// MaxRequestPayload returns the largest payload of a request with op, or 0
// for an op that is not a request.
func MaxRequestPayload(op Op) uint32 {
	switch op {
	case OpHello:
		return uint32(PayloadSize[HelloRequest]())
	case OpGetCapset:
		return uint32(PayloadSize[GetCapsetRequest]())
	case OpCtxCreate:
		return uint32(PayloadSize[CtxCreateRequest]() + MaxContextNameBytes)
	case OpCtxDestroy, OpTestConfine:
		return 0
	case OpBlobCreate:
		return uint32(PayloadSize[BlobCreateRequest]())
	case OpResUnref:
		return uint32(PayloadSize[ResUnrefRequest]())
	case OpSubmit:
		return uint32(PayloadSize[SubmitRequest]() + MaxSubmitBytes)
	case OpResCreate:
		return uint32(PayloadSize[ResCreateRequest]())
	case OpTransfer:
		return uint32(PayloadSize[TransferRequest]())
	default:
		return 0
	}
}

func eventPayloadSize(op Op) int {
	switch op {
	case OpFenceDone:
		return PayloadSize[FenceDoneEvent]()
	case OpCtxLost:
		return PayloadSize[CtxLostEvent]()
	default:
		return -1
	}
}

// ParseHeader decodes b, which must be exactly HeaderSize bytes, and
// validates it for dir. Every error wraps ErrMalformed.
func ParseHeader(b []byte, dir Direction) (Header, error) {
	if len(b) != HeaderSize {
		return Header{}, fmt.Errorf("%w: header length %d, want %d", ErrMalformed, len(b), HeaderSize)
	}
	var h Header
	if _, err := binary.Decode(b, binary.LittleEndian, &h); err != nil {
		return Header{}, fmt.Errorf("%w: decode header: %v", ErrMalformed, err)
	}
	if h.Magic != Magic {
		return Header{}, fmt.Errorf("%w: magic %#x, want %#x", ErrMalformed, h.Magic, Magic)
	}
	if h.Flags&^knownFlags != 0 {
		return Header{}, fmt.Errorf("%w: unknown flags %#x", ErrMalformed, h.Flags)
	}

	switch dir {
	case ToRenderer:
		return validateToRenderer(h)
	case FromRenderer:
		return validateFromRenderer(h)
	default:
		return Header{}, fmt.Errorf("%w: unknown direction %d", ErrMalformed, dir)
	}
}

func validateToRenderer(h Header) (Header, error) {
	if h.Flags != 0 || h.Status != StatusOK {
		return Header{}, fmt.Errorf("%w: request has flags %#x and status %s", ErrMalformed, h.Flags, h.Status)
	}
	if !h.Op.IsRequest() {
		return Header{}, fmt.Errorf("%w: op %s is not a request", ErrMalformed, h.Op)
	}
	if h.Seq == 0 {
		return Header{}, fmt.Errorf("%w: request %s has seq 0", ErrMalformed, h.Op)
	}
	if h.Op == OpHello || h.Op == OpGetCapset || h.Op == OpTestConfine {
		if h.CtxID != 0 {
			return Header{}, fmt.Errorf("%w: request %s has ctx_id %d, want 0", ErrMalformed, h.Op, h.CtxID)
		}
	} else if h.CtxID == 0 {
		return Header{}, fmt.Errorf("%w: request %s has ctx_id 0", ErrMalformed, h.Op)
	}
	if maxLen := MaxRequestPayload(h.Op); h.PayloadLen > maxLen {
		return Header{}, fmt.Errorf("%w: request %s payload_len %d exceeds max %d", ErrMalformed, h.Op, h.PayloadLen, maxLen)
	}
	return h, nil
}

func validateFromRenderer(h Header) (Header, error) {
	isReply := h.Flags&FlagReply != 0
	isEvent := h.Flags&FlagEvent != 0
	if isReply == isEvent {
		return Header{}, fmt.Errorf("%w: flags %#x must set exactly one of reply or event", ErrMalformed, h.Flags)
	}

	if isEvent {
		if !h.Op.IsEvent() {
			return Header{}, fmt.Errorf("%w: event op %s is not an event", ErrMalformed, h.Op)
		}
		if h.Seq != 0 {
			return Header{}, fmt.Errorf("%w: event %s has seq %d, want 0", ErrMalformed, h.Op, h.Seq)
		}
		if h.Status != StatusOK {
			return Header{}, fmt.Errorf("%w: event %s has status %s, want OK", ErrMalformed, h.Op, h.Status)
		}
		if h.CtxID == 0 {
			return Header{}, fmt.Errorf("%w: event %s has ctx_id 0", ErrMalformed, h.Op)
		}
		if h.Flags&FlagFD != 0 {
			return Header{}, fmt.Errorf("%w: event %s has FlagFD set", ErrMalformed, h.Op)
		}
		if wantLen := eventPayloadSize(h.Op); int(h.PayloadLen) != wantLen {
			return Header{}, fmt.Errorf("%w: event %s payload_len %d, want %d", ErrMalformed, h.Op, h.PayloadLen, wantLen)
		}
		return h, nil
	}

	if !h.Op.IsRequest() {
		return Header{}, fmt.Errorf("%w: reply op %s is not a request op", ErrMalformed, h.Op)
	}
	if h.Seq == 0 {
		return Header{}, fmt.Errorf("%w: reply %s has seq 0", ErrMalformed, h.Op)
	}
	if !h.Status.Known() {
		return Header{}, fmt.Errorf("%w: reply %s has unknown status %d", ErrMalformed, h.Op, h.Status)
	}
	if h.PayloadLen > MaxReplyPayload {
		return Header{}, fmt.Errorf("%w: reply %s payload_len %d exceeds max %d", ErrMalformed, h.Op, h.PayloadLen, MaxReplyPayload)
	}
	if h.Status != StatusOK {
		if h.PayloadLen != 0 {
			return Header{}, fmt.Errorf("%w: error reply %s (%s) has payload_len %d, want 0", ErrMalformed, h.Op, h.Status, h.PayloadLen)
		}
		if h.Flags&FlagFD != 0 {
			return Header{}, fmt.Errorf("%w: error reply %s (%s) has FlagFD set", ErrMalformed, h.Op, h.Status)
		}
	}
	if h.Flags&FlagFD != 0 && h.Op != OpBlobCreate && h.Op != OpResCreate {
		return Header{}, fmt.Errorf("%w: reply %s has FlagFD set", ErrMalformed, h.Op)
	}
	return h, nil
}
