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
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// HelloRequest is the payload of a HELLO request.
type HelloRequest struct {
	Version uint32 `c:"version"`
	Mode    Mode   `c:"mode"` // the mode that the Sentry started the renderer with
}

// HelloReply is the fixed prefix of a HELLO reply, followed by NumCapsets
// CapsetInfo entries.
type HelloReply struct {
	Version    uint32   `c:"version"`
	NumCapsets uint32   `c:"num_capsets"`
	Mode       Mode     `c:"mode"`     // the mode that the renderer serves
	Reserved   uint32   `c:"reserved"` // 0
	Build      [56]byte `c:"build"`
}

// CapsetInfo describes one capset advertised in a HELLO reply.
type CapsetInfo struct {
	ID         uint32 `c:"id"`
	MaxVersion uint32 `c:"max_version"`
	MaxSize    uint32 `c:"max_size"`
	Reserved   uint32 `c:"reserved"`
}

// GetCapsetRequest is the payload of a GET_CAPSET request.
type GetCapsetRequest struct {
	ID      uint32 `c:"id"`
	Version uint32 `c:"version"`
}

// CtxCreateRequest is the fixed prefix of a CTX_CREATE request, followed by
// NameLen name bytes.
type CtxCreateRequest struct {
	CapsetID uint32 `c:"capset_id"`
	NameLen  uint32 `c:"name_len"`
}

// BlobCreateRequest is the payload of a BLOB_CREATE request.
type BlobCreateRequest struct {
	ResID     uint32 `c:"res_id"`
	BlobMem   uint32 `c:"blob_mem"`
	BlobFlags uint32 `c:"blob_flags"`
	Reserved  uint32 `c:"reserved"`
	BlobID    uint64 `c:"blob_id"`
	Size      uint64 `c:"size"`
}

// BlobCreateReply is the payload of a BLOB_CREATE reply.
type BlobCreateReply struct {
	HostSize uint64 `c:"host_size"`
	MapInfo  uint32 `c:"map_info"`
	FDType   uint32 `c:"fd_type"`
}

// ResUnrefRequest is the payload of a RES_UNREF request.
type ResUnrefRequest struct {
	ResID    uint32 `c:"res_id"`
	Reserved uint32 `c:"reserved"`
}

// SubmitRequest is the fixed prefix of a SUBMIT request, followed by CmdLen
// command bytes.
type SubmitRequest struct {
	CmdLen   uint32 `c:"cmd_len"`
	Flags    uint32 `c:"flags"`
	RingIdx  uint32 `c:"ring_idx"`
	Reserved uint32 `c:"reserved"`
	FenceID  uint64 `c:"fence_id"`
}

// FenceDoneEvent is the payload of a FENCE_DONE event.
type FenceDoneEvent struct {
	RingIdx  uint32 `c:"ring_idx"`
	Reserved uint32 `c:"reserved"`
	FenceID  uint64 `c:"fence_id"`
}

// CtxLostEvent is the payload of a CTX_LOST event.
type CtxLostEvent struct {
	Reason   uint32 `c:"reason"`
	Reserved uint32 `c:"reserved"`
}

// ConfineCheck numbers one confinement check of the renderer.
type ConfineCheck uint8

const (
	ConfineCheckFork    ConfineCheck = 0 // fork()
	ConfineCheckExec    ConfineCheck = 1 // execl("/usr/bin/false") in the renderer
	ConfineCheckRead    ConfineCheck = 2 // open("/etc/passwd", O_RDONLY)
	ConfineCheckCreate  ConfineCheck = 3 // open("/private/tmp/gvx-gpu-selftest-<pid>", O_CREAT|O_EXCL|O_WRONLY)
	ConfineCheckConnect ConfineCheck = 4 // connect to 127.0.0.1:9 over TCP
	ConfineChecks                    = 5 // number of confinement checks
)

// ConfineResult is the outcome of one confinement check.
type ConfineResult uint8

const (
	ConfineNotRun     ConfineResult = 0
	ConfineDenied     ConfineResult = 1 // the profile refused the operation
	ConfineAllowed    ConfineResult = 2 // the operation succeeded (confinement failure)
	ConfineUnexpected ConfineResult = 3 // unexpected errno outside the profile denial set
)

// TestConfineReply is the reply payload of TEST_CONFINE.
type TestConfineReply struct {
	Checks  uint32   `c:"checks"`
	Results [8]uint8 `c:"results"`
}

// ResCreateRequest is the payload of a RES_CREATE request (virgl mode). The
// renderer creates a vrend resource, a shared-memory backing of at least Size
// bytes, attaches the backing, and attaches the resource to the context of
// the header.
type ResCreateRequest struct {
	ResID     uint32 `c:"res_id"`
	Target    uint32 `c:"target"`
	Format    uint32 `c:"format"`
	Bind      uint32 `c:"bind"`
	Width     uint32 `c:"width"`
	Height    uint32 `c:"height"`
	Depth     uint32 `c:"depth"`
	ArraySize uint32 `c:"array_size"`
	LastLevel uint32 `c:"last_level"`
	NrSamples uint32 `c:"nr_samples"`
	Flags     uint32 `c:"flags"`
	Reserved  uint32 `c:"reserved"`
	Size      uint64 `c:"size"` // backing bytes requested by the guest, 1..MaxBlobBytes
}

// ResCreateReply is the payload of a successful RES_CREATE reply. The reply
// has FlagFD and carries the backing descriptor.
type ResCreateReply struct {
	HostSize uint64 `c:"host_size"` // fstat size of the backing, a multiple of HostBlobAlign
	FDType   uint32 `c:"fd_type"`   // FDTypeShm
	Reserved uint32 `c:"reserved"`
}

// TransferRequest is the payload of a TRANSFER request (virgl mode). The
// renderer copies between the attached backing of ResID and the vrend
// resource, in the context of the header, and replies after the copy ends.
type TransferRequest struct {
	ResID       uint32 `c:"res_id"`
	Direction   uint32 `c:"direction"` // TransferToHost or TransferFromHost
	Level       uint32 `c:"level"`
	Stride      uint32 `c:"stride"`
	LayerStride uint32 `c:"layer_stride"`
	BoxX        uint32 `c:"box_x"`
	BoxY        uint32 `c:"box_y"`
	BoxZ        uint32 `c:"box_z"`
	BoxW        uint32 `c:"box_w"`
	BoxH        uint32 `c:"box_h"`
	BoxD        uint32 `c:"box_d"`
	Reserved    uint32 `c:"reserved"`
	Offset      uint64 `c:"offset"` // byte offset into the backing
}

// fixedPayload lists the fixed-size payload structs.
type fixedPayload interface {
	HelloRequest | HelloReply | CapsetInfo | GetCapsetRequest | CtxCreateRequest |
		BlobCreateRequest | BlobCreateReply | ResUnrefRequest | SubmitRequest |
		FenceDoneEvent | CtxLostEvent | TestConfineReply |
		ResCreateRequest | ResCreateReply | TransferRequest
}

// PayloadSize returns the encoded size of T.
func PayloadSize[T fixedPayload]() int {
	var zero T
	n := binary.Size(zero)
	if n < 0 {
		panic(fmt.Sprintf("gpuproto: non-fixed payload type %T", zero))
	}
	return n
}

// AppendPayload appends the little-endian encoding of v to dst.
func AppendPayload[T fixedPayload](dst []byte, v T) []byte {
	out, err := binary.Append(dst, binary.LittleEndian, v)
	if err != nil {
		panic(err)
	}
	return out
}

// DecodePayload decodes b, which must be exactly PayloadSize[T]() bytes.
// A wrong length returns an error that wraps ErrMalformed.
func DecodePayload[T fixedPayload](b []byte) (T, error) {
	var v T
	want := PayloadSize[T]()
	if len(b) != want {
		return v, fmt.Errorf("%w: payload length %d for %T, want %d", ErrMalformed, len(b), v, want)
	}
	if _, err := binary.Decode(b, binary.LittleEndian, &v); err != nil {
		return v, fmt.Errorf("%w: decode %T: %v", ErrMalformed, v, err)
	}
	return v, nil
}

// AppendCtxCreate appends a CTX_CREATE payload. A name longer than
// MaxContextNameBytes returns a *StatusError (OpCtxCreate, StatusInvalid).
func AppendCtxCreate(dst []byte, capsetID uint32, name string) ([]byte, error) {
	if len(name) > MaxContextNameBytes {
		return nil, &StatusError{Op: OpCtxCreate, Status: StatusInvalid}
	}
	dst = AppendPayload(dst, CtxCreateRequest{
		CapsetID: capsetID,
		NameLen:  uint32(len(name)),
	})
	return append(dst, name...), nil
}

// DecodeCtxCreate decodes a CTX_CREATE payload: NameLen must be at most
// MaxContextNameBytes and len(b) must be exactly 8 + NameLen.
func DecodeCtxCreate(b []byte) (capsetID uint32, name string, err error) {
	prefixLen := PayloadSize[CtxCreateRequest]()
	if len(b) < prefixLen {
		return 0, "", fmt.Errorf("%w: CTX_CREATE payload length %d below %d", ErrMalformed, len(b), prefixLen)
	}
	req, err := DecodePayload[CtxCreateRequest](b[:prefixLen])
	if err != nil {
		return 0, "", err
	}
	if req.NameLen > MaxContextNameBytes {
		return 0, "", fmt.Errorf("%w: CTX_CREATE name_len %d exceeds max %d", ErrMalformed, req.NameLen, MaxContextNameBytes)
	}
	if want := prefixLen + int(req.NameLen); len(b) != want {
		return 0, "", fmt.Errorf("%w: CTX_CREATE payload length %d, want %d", ErrMalformed, len(b), want)
	}
	return req.CapsetID, string(b[prefixLen:]), nil
}

// AppendSubmit appends a SUBMIT payload. cmd must be a multiple of 4 bytes
// and at most MaxSubmitBytes; fence, when not nil, must pass Validate. A
// violation returns a *StatusError (OpSubmit, StatusInvalid).
func AppendSubmit(dst []byte, cmd []byte, fence *Fence) ([]byte, error) {
	if len(cmd)%4 != 0 || len(cmd) > MaxSubmitBytes {
		return nil, &StatusError{Op: OpSubmit, Status: StatusInvalid}
	}
	req := SubmitRequest{
		CmdLen: uint32(len(cmd)),
	}
	if fence != nil {
		if err := fence.Validate(); err != nil {
			return nil, err
		}
		req.Flags = SubmitFlagFence
		req.RingIdx = fence.RingIdx
		req.FenceID = fence.ID
	}
	dst = AppendPayload(dst, req)
	return append(dst, cmd...), nil
}

// DecodeSubmit decodes a SUBMIT payload and returns cmd as a subslice of b.
// fence is nil when SubmitFlagFence is clear.
func DecodeSubmit(b []byte) (cmd []byte, fence *Fence, err error) {
	prefixLen := PayloadSize[SubmitRequest]()
	if len(b) < prefixLen {
		return nil, nil, fmt.Errorf("%w: SUBMIT payload length %d below %d", ErrMalformed, len(b), prefixLen)
	}
	req, err := DecodePayload[SubmitRequest](b[:prefixLen])
	if err != nil {
		return nil, nil, err
	}
	if req.Flags&^SubmitFlagFence != 0 {
		return nil, nil, fmt.Errorf("%w: SUBMIT unknown flags %#x", ErrMalformed, req.Flags)
	}
	if req.CmdLen > MaxSubmitBytes || req.CmdLen%4 != 0 {
		return nil, nil, fmt.Errorf("%w: SUBMIT cmd_len %d is invalid", ErrMalformed, req.CmdLen)
	}
	if want := prefixLen + int(req.CmdLen); len(b) != want {
		return nil, nil, fmt.Errorf("%w: SUBMIT payload length %d, want %d", ErrMalformed, len(b), want)
	}
	if req.Flags&SubmitFlagFence != 0 {
		f := Fence{RingIdx: req.RingIdx, ID: req.FenceID}
		if err := f.Validate(); err != nil {
			return nil, nil, fmt.Errorf("%w: SUBMIT invalid fence (ring=%d, id=%d)", ErrMalformed, req.RingIdx, req.FenceID)
		}
		fence = &f
	}
	return b[prefixLen:], fence, nil
}

// HelloInfo is the decoded HELLO reply.
type HelloInfo struct {
	Version uint32
	Mode    Mode
	Build   string
	Caps    []CapsetInfo
}

// AppendHello appends a HELLO reply payload. len(info.Caps) must be at most
// MaxCapsets. info.Version is ignored; the payload carries Version.
func AppendHello(dst []byte, info HelloInfo) ([]byte, error) {
	if len(info.Caps) > MaxCapsets {
		return nil, fmt.Errorf("%w: HELLO reply has %d capsets, max %d", ErrMalformed, len(info.Caps), MaxCapsets)
	}
	rep := HelloReply{
		Version:    Version,
		NumCapsets: uint32(len(info.Caps)),
		Mode:       info.Mode,
	}
	copy(rep.Build[:len(rep.Build)-1], info.Build)
	dst = AppendPayload(dst, rep)
	for _, capInfo := range info.Caps {
		dst = AppendPayload(dst, capInfo)
	}
	return dst, nil
}

// DecodeHello decodes a HELLO reply payload. NumCapsets must be at most
// MaxCapsets, Reserved must be 0, len(b) must be exactly 72 + 16*NumCapsets,
// and every capset must have MaxVersion <= MaxCapsetVersion and
// 0 < MaxSize <= MaxCapsetBytes. Build is the Build field up to the first
// NUL byte, with every byte outside 0x20 to 0x7e replaced by '?'. It does not
// validate Mode; the client compares Mode with the requested mode.
func DecodeHello(b []byte) (HelloInfo, error) {
	prefixLen := PayloadSize[HelloReply]()
	capLen := PayloadSize[CapsetInfo]()
	if len(b) < prefixLen {
		return HelloInfo{}, fmt.Errorf("%w: HELLO reply length %d below %d", ErrMalformed, len(b), prefixLen)
	}
	rep, err := DecodePayload[HelloReply](b[:prefixLen])
	if err != nil {
		return HelloInfo{}, err
	}
	if rep.Reserved != 0 {
		return HelloInfo{}, fmt.Errorf("%w: HELLO reply reserved %#x, want 0", ErrMalformed, rep.Reserved)
	}
	if rep.NumCapsets > MaxCapsets {
		return HelloInfo{}, fmt.Errorf("%w: HELLO reply num_capsets %d exceeds max %d", ErrMalformed, rep.NumCapsets, MaxCapsets)
	}
	if want := prefixLen + int(rep.NumCapsets)*capLen; len(b) != want {
		return HelloInfo{}, fmt.Errorf("%w: HELLO reply length %d, want %d", ErrMalformed, len(b), want)
	}
	caps := make([]CapsetInfo, rep.NumCapsets)
	for i := range caps {
		off := prefixLen + i*capLen
		info, err := DecodePayload[CapsetInfo](b[off : off+capLen])
		if err != nil {
			return HelloInfo{}, err
		}
		if info.MaxVersion > MaxCapsetVersion {
			return HelloInfo{}, fmt.Errorf("%w: capset %d max_version %d exceeds max %d", ErrMalformed, info.ID, info.MaxVersion, MaxCapsetVersion)
		}
		if info.MaxSize == 0 || info.MaxSize > MaxCapsetBytes {
			return HelloInfo{}, fmt.Errorf("%w: capset %d max_size %d out of range 1..%d", ErrMalformed, info.ID, info.MaxSize, MaxCapsetBytes)
		}
		caps[i] = info
	}
	return HelloInfo{
		Version: rep.Version,
		Mode:    rep.Mode,
		Build:   sanitizeBuild(rep.Build[:]),
		Caps:    caps,
	}, nil
}

func sanitizeBuild(raw []byte) string {
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	var sb strings.Builder
	sb.Grow(len(raw))
	for _, c := range raw {
		if c < 0x20 || c > 0x7e {
			sb.WriteByte('?')
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}
