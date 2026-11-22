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

// Package control implements the gvx-ctrl/2 framed control socket protocol,
// endpoint binding, authentication, capability filtering, and legacy v1
// checkpoint compatibility.
package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

const (
	// ProtocolVersion is the current control wire protocol version.
	ProtocolVersion = 2

	// Preface identifies a v2 binary-framed control connection.
	Preface = "GVX2"

	// FrameHeaderSize is the fixed 12-byte big-endian frame header length.
	FrameHeaderSize = 12

	// HandshakeMaxFrameBytes bounds frames before HELLO completes.
	HandshakeMaxFrameBytes = 64 << 10

	// DefaultMaxFrameBytes is the default per-frame payload ceiling.
	DefaultMaxFrameBytes = 256 << 10

	// AbsoluteMaxFrameBytes is the hard protocol ceiling on any frame payload.
	AbsoluteMaxFrameBytes = 4 << 20

	// InitialStreamWindow is the initial per-stream credit window in bytes.
	InitialStreamWindow = 1 << 20

	// WindowRefillThreshold triggers a WINDOW_UPDATE once this many bytes are consumed.
	WindowRefillThreshold = 256 << 10
)

// FrameType identifies the semantic role of one wire frame.
type FrameType uint8

const (
	FrameHello        FrameType = 0x01
	FrameRequest      FrameType = 0x02
	FrameResponse     FrameType = 0x03
	FrameData         FrameType = 0x04
	FrameEvent        FrameType = 0x05
	FrameWindowUpdate FrameType = 0x06
	FrameCancel       FrameType = 0x07
	FramePing         FrameType = 0x08
	FramePong         FrameType = 0x09
	FrameGoAway       FrameType = 0x0A
)

// FrameFlags carries per-frame modifiers.
type FrameFlags uint8

const (
	// FlagEndStream marks half-close EOF for (StreamID, Channel).
	FlagEndStream FrameFlags = 1 << 0
	// FlagCompressedZstd marks a zstd-compressed payload.
	FlagCompressedZstd FrameFlags = 1 << 1
	// FlagHasFDs marks a frame accompanied by Unix SCM_RIGHTS file descriptors.
	FlagHasFDs FrameFlags = 1 << 2
)

// Channel identifies a byte sub-stream inside FrameData frames.
type Channel uint16

const (
	ChannelGeneric Channel = 0
	ChannelStdin   Channel = 1
	ChannelStdout  Channel = 2
	ChannelStderr  Channel = 3
)

// ErrorCode classifies structured control protocol errors.
type ErrorCode string

const (
	CodeInvalidArgument   ErrorCode = "INVALID_ARGUMENT"
	CodeUnauthorized      ErrorCode = "UNAUTHORIZED"
	CodeForbiddenByPolicy ErrorCode = "FORBIDDEN_BY_POLICY"
	CodeLockdownDenied    ErrorCode = "LOCKDOWN_DENIED"
	CodeUnsupported       ErrorCode = "UNSUPPORTED"
	CodeAlreadyPaused     ErrorCode = "ALREADY_PAUSED"
	CodeNotPaused         ErrorCode = "NOT_PAUSED"
	CodeNotFound          ErrorCode = "NOT_FOUND"
	CodeAlreadyExists     ErrorCode = "ALREADY_EXISTS"
	CodeBusy              ErrorCode = "BUSY"
	CodeLimitExceeded     ErrorCode = "LIMIT_EXCEEDED"
	CodeExecActive        ErrorCode = "EXEC_ACTIVE"
	CodeSandboxExiting    ErrorCode = "SANDBOX_EXITING"
	CodeInternal          ErrorCode = "INTERNAL"
)

// ProtoError is a structured error returned over the control protocol.
type ProtoError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	Errno     int       `json:"errno,omitempty"`
	Retryable bool      `json:"retryable,omitempty"`
}

// Error implements error.
func (e *ProtoError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return string(e.Code)
}

// NewError builds a structured ProtoError.
func NewError(code ErrorCode, msg string) *ProtoError {
	return &ProtoError{Code: code, Message: msg}
}

// NewErrorf builds a formatted structured ProtoError.
func NewErrorf(code ErrorCode, format string, args ...any) *ProtoError {
	return &ProtoError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// IsCode reports whether err wraps a *ProtoError with code.
func IsCode(err error, code ErrorCode) bool {
	var pe *ProtoError
	return errors.As(err, &pe) && pe.Code == code
}

// ErrFrameTooLarge reports a frame payload exceeding the negotiated ceiling.
var ErrFrameTooLarge = errors.New("control: frame payload exceeds maximum size")

// ErrStreamClosed reports an operation on a closed control stream.
var ErrStreamClosed = errors.New("control: stream closed")

// ErrConnClosed reports an operation on a closed control connection.
var ErrConnClosed = errors.New("control: connection closed")

// Frame is one decoded wire message.
type Frame struct {
	Type     FrameType
	Flags    FrameFlags
	Channel  Channel
	StreamID uint32
	Payload  []byte
	FDs      []int
}

var (
	zstdEncOnce sync.Once
	zstdEnc     *zstd.Encoder
	zstdEncErr  error

	zstdDecOnce sync.Once
	zstdDec     *zstd.Decoder
	zstdDecErr  error
)

func getZstdEncoder() (*zstd.Encoder, error) {
	zstdEncOnce.Do(func() {
		zstdEnc, zstdEncErr = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	})
	return zstdEnc, zstdEncErr
}

func getZstdDecoder() (*zstd.Decoder, error) {
	zstdDecOnce.Do(func() {
		zstdDec, zstdDecErr = zstd.NewReader(nil,
			zstd.WithDecoderMaxMemory(AbsoluteMaxFrameBytes*2),
			zstd.WithDecoderMaxWindow(AbsoluteMaxFrameBytes),
		)
	})
	return zstdDec, zstdDecErr
}

// WriteFrame encodes and writes one frame to w. When FlagCompressedZstd is set
// and payload is non-empty, WriteFrame compresses payload before writing.
func WriteFrame(w io.Writer, f Frame, maxPayload int) error {
	if maxPayload <= 0 || maxPayload > AbsoluteMaxFrameBytes {
		maxPayload = DefaultMaxFrameBytes
	}
	payload := f.Payload
	flags := f.Flags
	if flags&FlagCompressedZstd != 0 && len(payload) > 0 {
		enc, err := getZstdEncoder()
		if err != nil {
			return fmt.Errorf("control: init zstd encoder: %w", err)
		}
		compressed := enc.EncodeAll(payload, nil)
		if len(compressed) < len(payload) {
			payload = compressed
		} else {
			flags &^= FlagCompressedZstd
		}
	}
	if len(payload) > maxPayload {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(payload), maxPayload)
	}
	var hdr [FrameHeaderSize]byte
	hdr[0] = byte(f.Type)
	hdr[1] = byte(flags)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(f.Channel))
	binary.BigEndian.PutUint32(hdr[4:8], f.StreamID)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame reads and decodes one frame from r, bounding both wire length and
// decompressed length by maxPayload.
func ReadFrame(r io.Reader, maxPayload int) (Frame, error) {
	if maxPayload <= 0 || maxPayload > AbsoluteMaxFrameBytes {
		maxPayload = DefaultMaxFrameBytes
	}
	var hdr [FrameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	length := int(binary.BigEndian.Uint32(hdr[8:12]))
	if length < 0 || length > maxPayload {
		return Frame{}, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, length, maxPayload)
	}
	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}
	flags := FrameFlags(hdr[1])
	if flags&FlagCompressedZstd != 0 && len(payload) > 0 {
		dec, err := getZstdDecoder()
		if err != nil {
			return Frame{}, fmt.Errorf("control: init zstd decoder: %w", err)
		}
		decoded, err := dec.DecodeAll(payload, nil)
		if err != nil {
			return Frame{}, fmt.Errorf("control: decode zstd frame: %w", err)
		}
		if len(decoded) > maxPayload {
			return Frame{}, fmt.Errorf("%w: decompressed %d > %d", ErrFrameTooLarge, len(decoded), maxPayload)
		}
		payload = decoded
		flags &^= FlagCompressedZstd
	}
	return Frame{
		Type:     FrameType(hdr[0]),
		Flags:    flags,
		Channel:  Channel(binary.BigEndian.Uint16(hdr[2:4])),
		StreamID: binary.BigEndian.Uint32(hdr[4:8]),
		Payload:  payload,
	}, nil
}
