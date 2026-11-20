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

package gpuproto_test

import (
	"bytes"
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

func TestHeaderRoundTrip(t *testing.T) {
	requestOps := []gpuproto.Op{
		gpuproto.OpHello,
		gpuproto.OpGetCapset,
		gpuproto.OpCtxCreate,
		gpuproto.OpCtxDestroy,
		gpuproto.OpBlobCreate,
		gpuproto.OpResUnref,
		gpuproto.OpSubmit,
		gpuproto.OpTestConfine,
	}
	wantMagicPrefix := []byte{0x47, 0x50, 0x55, 0x31}

	check := func(t *testing.T, h gpuproto.Header, dir gpuproto.Direction) {
		t.Helper()
		raw := gpuproto.AppendHeader(nil, h)
		if len(raw) != gpuproto.HeaderSize {
			t.Fatalf("encoded length = %d, want %d", len(raw), gpuproto.HeaderSize)
		}
		if !bytes.Equal(raw[:4], wantMagicPrefix) {
			t.Fatalf("magic bytes = % x, want % x", raw[:4], wantMagicPrefix)
		}
		got, err := gpuproto.ParseHeader(raw, dir)
		if err != nil {
			t.Fatalf("ParseHeader(%+v, %d): %v", h, dir, err)
		}
		if got != h {
			t.Fatalf("ParseHeader = %+v, want %+v", got, h)
		}
	}

	for _, op := range requestOps {
		ctxID := uint32(3)
		if op == gpuproto.OpHello || op == gpuproto.OpGetCapset || op == gpuproto.OpTestConfine {
			ctxID = 0
		}
		t.Run("request/"+op.String(), func(t *testing.T) {
			h := gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         op,
				Seq:        7,
				CtxID:      ctxID,
				PayloadLen: gpuproto.MaxRequestPayload(op),
				Status:     gpuproto.StatusOK,
			}
			check(t, h, gpuproto.ToRenderer)
		})
		t.Run("reply_ok/"+op.String(), func(t *testing.T) {
			h := gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         op,
				Flags:      gpuproto.FlagReply,
				Seq:        7,
				CtxID:      ctxID,
				PayloadLen: gpuproto.MaxReplyPayload,
				Status:     gpuproto.StatusOK,
			}
			check(t, h, gpuproto.FromRenderer)
		})
		t.Run("reply_invalid/"+op.String(), func(t *testing.T) {
			h := gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         op,
				Flags:      gpuproto.FlagReply,
				Seq:        7,
				CtxID:      ctxID,
				PayloadLen: 0,
				Status:     gpuproto.StatusInvalid,
			}
			check(t, h, gpuproto.FromRenderer)
		})
	}

	eventCases := []struct {
		op         gpuproto.Op
		payloadLen uint32
	}{
		{gpuproto.OpFenceDone, uint32(gpuproto.PayloadSize[gpuproto.FenceDoneEvent]())},
		{gpuproto.OpCtxLost, uint32(gpuproto.PayloadSize[gpuproto.CtxLostEvent]())},
	}
	for _, ec := range eventCases {
		t.Run("event/"+ec.op.String(), func(t *testing.T) {
			h := gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         ec.op,
				Flags:      gpuproto.FlagEvent,
				Seq:        0,
				CtxID:      3,
				PayloadLen: ec.payloadLen,
				Status:     gpuproto.StatusOK,
			}
			check(t, h, gpuproto.FromRenderer)
		})
	}

	t.Run("reply_blob_create_fd", func(t *testing.T) {
		h := gpuproto.Header{
			Magic:      gpuproto.Magic,
			Op:         gpuproto.OpBlobCreate,
			Flags:      gpuproto.FlagReply | gpuproto.FlagFD,
			Seq:        7,
			CtxID:      3,
			PayloadLen: uint32(gpuproto.PayloadSize[gpuproto.BlobCreateReply]()),
			Status:     gpuproto.StatusOK,
		}
		check(t, h, gpuproto.FromRenderer)
	})
}

func TestParseHeaderRejects(t *testing.T) {
	validReq := func() gpuproto.Header {
		return gpuproto.Header{
			Magic:      gpuproto.Magic,
			Op:         gpuproto.OpSubmit,
			Seq:        1,
			CtxID:      2,
			PayloadLen: uint32(gpuproto.PayloadSize[gpuproto.SubmitRequest]()),
			Status:     gpuproto.StatusOK,
		}
	}
	validReply := func() gpuproto.Header {
		return gpuproto.Header{
			Magic:      gpuproto.Magic,
			Op:         gpuproto.OpBlobCreate,
			Flags:      gpuproto.FlagReply,
			Seq:        1,
			CtxID:      2,
			PayloadLen: uint32(gpuproto.PayloadSize[gpuproto.BlobCreateReply]()),
			Status:     gpuproto.StatusOK,
		}
	}
	validEvent := func() gpuproto.Header {
		return gpuproto.Header{
			Magic:      gpuproto.Magic,
			Op:         gpuproto.OpFenceDone,
			Flags:      gpuproto.FlagEvent,
			Seq:        0,
			CtxID:      2,
			PayloadLen: uint32(gpuproto.PayloadSize[gpuproto.FenceDoneEvent]()),
			Status:     gpuproto.StatusOK,
		}
	}

	cases := []struct {
		name string
		raw  []byte
		dir  gpuproto.Direction
	}{
		{
			name: "short_23_bytes",
			raw:  gpuproto.AppendHeader(nil, validReq())[:gpuproto.HeaderSize-1],
			dir:  gpuproto.ToRenderer,
		},
		{
			name: "wrong_magic",
			raw: func() []byte {
				h := validReq()
				h.Magic ^= 1
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.ToRenderer,
		},
		{
			name: "unknown_flag_bit_3",
			raw: func() []byte {
				h := validReply()
				h.Flags |= 1 << 3
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "request_with_flag_reply",
			raw: func() []byte {
				h := validReq()
				h.Flags = gpuproto.FlagReply
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.ToRenderer,
		},
		{
			name: "request_with_status_invalid",
			raw: func() []byte {
				h := validReq()
				h.Status = gpuproto.StatusInvalid
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.ToRenderer,
		},
		{
			name: "request_with_seq_0",
			raw: func() []byte {
				h := validReq()
				h.Seq = 0
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.ToRenderer,
		},
		{
			name: "hello_request_with_ctx_id_1",
			raw: func() []byte {
				h := validReq()
				h.Op = gpuproto.OpHello
				h.CtxID = 1
				h.PayloadLen = uint32(gpuproto.PayloadSize[gpuproto.HelloRequest]())
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.ToRenderer,
		},
		{
			name: "submit_request_with_ctx_id_0",
			raw: func() []byte {
				h := validReq()
				h.CtxID = 0
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.ToRenderer,
		},
		{
			name: "submit_request_payload_too_large",
			raw: func() []byte {
				h := validReq()
				h.PayloadLen = gpuproto.MaxRequestPayload(gpuproto.OpSubmit) + 1
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.ToRenderer,
		},
		{
			name: "event_op_sent_to_renderer",
			raw: func() []byte {
				h := validReq()
				h.Op = gpuproto.OpFenceDone
				h.PayloadLen = uint32(gpuproto.PayloadSize[gpuproto.FenceDoneEvent]())
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.ToRenderer,
		},
		{
			name: "reply_and_event_both_set",
			raw: func() []byte {
				h := validReply()
				h.Flags = gpuproto.FlagReply | gpuproto.FlagEvent
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "neither_reply_nor_event",
			raw: func() []byte {
				h := validReply()
				h.Flags = 0
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "event_with_seq_1",
			raw: func() []byte {
				h := validEvent()
				h.Seq = 1
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "event_with_ctx_id_0",
			raw: func() []byte {
				h := validEvent()
				h.CtxID = 0
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "fence_done_payload_len_15",
			raw: func() []byte {
				h := validEvent()
				h.PayloadLen = uint32(gpuproto.PayloadSize[gpuproto.FenceDoneEvent]()) - 1
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "event_op_ctx_lost_with_flag_reply",
			raw: func() []byte {
				h := validReply()
				h.Op = gpuproto.OpCtxLost
				h.PayloadLen = uint32(gpuproto.PayloadSize[gpuproto.CtxLostEvent]())
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "reply_with_unknown_status_minus_35",
			raw: func() []byte {
				h := validReply()
				h.Status = gpuproto.Status(-35)
				h.PayloadLen = 0
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "reply_payload_too_large",
			raw: func() []byte {
				h := validReply()
				h.PayloadLen = gpuproto.MaxReplyPayload + 1
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "error_reply_with_payload_len_4",
			raw: func() []byte {
				h := validReply()
				h.Status = gpuproto.StatusInvalid
				h.PayloadLen = 4
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "error_reply_with_flag_fd",
			raw: func() []byte {
				h := validReply()
				h.Status = gpuproto.StatusInvalid
				h.PayloadLen = 0
				h.Flags |= gpuproto.FlagFD
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "submit_reply_with_flag_fd",
			raw: func() []byte {
				h := validReply()
				h.Op = gpuproto.OpSubmit
				h.Flags |= gpuproto.FlagFD
				h.PayloadLen = 0
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "reply_with_op_11",
			raw: func() []byte {
				h := validReply()
				h.Op = gpuproto.Op(11)
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "test_confine_request_with_ctx_id_1",
			raw: func() []byte {
				h := validReq()
				h.Op = gpuproto.OpTestConfine
				h.CtxID = 1
				h.PayloadLen = 0
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.ToRenderer,
		},
		{
			name: "test_confine_request_with_payload_len_1",
			raw: func() []byte {
				h := validReq()
				h.Op = gpuproto.OpTestConfine
				h.CtxID = 0
				h.PayloadLen = 1
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.ToRenderer,
		},
		{
			name: "invalid_direction_zero",
			raw:  gpuproto.AppendHeader(nil, validReq()),
			dir:  gpuproto.Direction(0),
		},
		{
			name: "event_with_status_invalid",
			raw: func() []byte {
				h := validEvent()
				h.Status = gpuproto.StatusInvalid
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
		{
			name: "event_with_flag_fd",
			raw: func() []byte {
				h := validEvent()
				h.Flags |= gpuproto.FlagFD
				return gpuproto.AppendHeader(nil, h)
			}(),
			dir: gpuproto.FromRenderer,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := gpuproto.ParseHeader(tc.raw, tc.dir)
			if !errors.Is(err, gpuproto.ErrMalformed) {
				t.Fatalf("ParseHeader error = %v, want wrapping ErrMalformed", err)
			}
		})
	}
}

func TestOpAndStatusNames(t *testing.T) {
	if got := gpuproto.OpBlobCreate.String(); got != "BLOB_CREATE" {
		t.Errorf("OpBlobCreate.String() = %q, want %q", got, "BLOB_CREATE")
	}
	if got := gpuproto.OpTestConfine.String(); got != "TEST_CONFINE" {
		t.Errorf("OpTestConfine.String() = %q, want %q", got, "TEST_CONFINE")
	}
	if !gpuproto.OpTestConfine.IsRequest() {
		t.Errorf("OpTestConfine.IsRequest() = false, want true")
	}
	if got := gpuproto.Op(11).String(); got != "OP(11)" {
		t.Errorf("Op(11).String() = %q, want %q", got, "OP(11)")
	}
	if got := gpuproto.StatusNotSupported.String(); got != "EOPNOTSUPP" {
		t.Errorf("StatusNotSupported.String() = %q, want %q", got, "EOPNOTSUPP")
	}
	if got := gpuproto.Status(-35).String(); got != "STATUS(-35)" {
		t.Errorf("Status(-35).String() = %q, want %q", got, "STATUS(-35)")
	}
	if gpuproto.Status(-35).Known() {
		t.Errorf("Status(-35).Known() = true, want false")
	}
}
