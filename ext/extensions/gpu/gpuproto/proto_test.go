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
	"slices"
	"testing"

	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
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
		gpuproto.OpResCreate,
		gpuproto.OpTransfer,
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
	t.Run("reply_res_create_fd", func(t *testing.T) {
		h := gpuproto.Header{
			Magic:      gpuproto.Magic,
			Op:         gpuproto.OpResCreate,
			Flags:      gpuproto.FlagReply | gpuproto.FlagFD,
			Seq:        7,
			CtxID:      3,
			PayloadLen: uint32(gpuproto.PayloadSize[gpuproto.ResCreateReply]()),
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
			name: "reply_with_op_13",
			raw: func() []byte {
				h := validReply()
				h.Op = gpuproto.Op(13)
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
	if got := gpuproto.Op(13).String(); got != "OP(13)" {
		t.Errorf("Op(13).String() = %q, want %q", got, "OP(13)")
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

func TestOpPredicates(t *testing.T) {
	cases := []struct {
		op        gpuproto.Op
		wantName  string
		wantReq   bool
		wantEvent bool
	}{
		{gpuproto.Op(0), "OP(0)", false, false},
		{gpuproto.OpHello, "HELLO", true, false},
		{gpuproto.OpFenceDone, "FENCE_DONE", false, true},
		{gpuproto.OpCtxLost, "CTX_LOST", false, true},
		{gpuproto.OpTestConfine, "TEST_CONFINE", true, false},
		{gpuproto.OpResCreate, "RES_CREATE", true, false},
		{gpuproto.OpTransfer, "TRANSFER", true, false},
		{gpuproto.Op(13), "OP(13)", false, false},
	}
	for _, tc := range cases {
		if got := tc.op.String(); got != tc.wantName {
			t.Errorf("Op(%d).String() = %q, want %q", tc.op, got, tc.wantName)
		}
		if got := tc.op.IsRequest(); got != tc.wantReq {
			t.Errorf("Op(%d).IsRequest() = %v, want %v", tc.op, got, tc.wantReq)
		}
		if got := tc.op.IsEvent(); got != tc.wantEvent {
			t.Errorf("Op(%d).IsEvent() = %v, want %v", tc.op, got, tc.wantEvent)
		}
	}
}

func TestParseHeaderNewOps(t *testing.T) {
	if got := gpuproto.MaxRequestPayload(gpuproto.OpResCreate); got != 56 {
		t.Fatalf("MaxRequestPayload(OpResCreate) = %d, want 56", got)
	}
	if got := gpuproto.MaxRequestPayload(gpuproto.OpTransfer); got != 56 {
		t.Fatalf("MaxRequestPayload(OpTransfer) = %d, want 56", got)
	}

	okCases := []struct {
		name string
		hdr  gpuproto.Header
		dir  gpuproto.Direction
	}{
		{
			name: "res_create_request_ok",
			hdr: gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpResCreate,
				Seq:        1,
				CtxID:      2,
				PayloadLen: 56,
			},
			dir: gpuproto.ToRenderer,
		},
		{
			name: "transfer_request_ok",
			hdr: gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpTransfer,
				Seq:        1,
				CtxID:      2,
				PayloadLen: 56,
			},
			dir: gpuproto.ToRenderer,
		},
		{
			name: "res_create_reply_with_fd_ok",
			hdr: gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpResCreate,
				Flags:      gpuproto.FlagReply | gpuproto.FlagFD,
				Seq:        1,
				CtxID:      2,
				PayloadLen: 16,
				Status:     gpuproto.StatusOK,
			},
			dir: gpuproto.FromRenderer,
		},
	}
	for _, tc := range okCases {
		t.Run(tc.name, func(t *testing.T) {
			raw := gpuproto.AppendHeader(nil, tc.hdr)
			got, err := gpuproto.ParseHeader(raw, tc.dir)
			if err != nil {
				t.Fatalf("ParseHeader(%s): %v", tc.name, err)
			}
			if got != tc.hdr {
				t.Fatalf("ParseHeader(%s) = %+v, want %+v", tc.name, got, tc.hdr)
			}
		})
	}

	rejectCases := []struct {
		name string
		hdr  gpuproto.Header
		dir  gpuproto.Direction
	}{
		{
			name: "res_create_request_ctx_0",
			hdr: gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpResCreate,
				Seq:        1,
				CtxID:      0,
				PayloadLen: 56,
			},
			dir: gpuproto.ToRenderer,
		},
		{
			name: "transfer_request_ctx_0",
			hdr: gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpTransfer,
				Seq:        1,
				CtxID:      0,
				PayloadLen: 56,
			},
			dir: gpuproto.ToRenderer,
		},
		{
			name: "res_create_request_payload_57",
			hdr: gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpResCreate,
				Seq:        1,
				CtxID:      2,
				PayloadLen: 57,
			},
			dir: gpuproto.ToRenderer,
		},
		{
			name: "transfer_request_payload_57",
			hdr: gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpTransfer,
				Seq:        1,
				CtxID:      2,
				PayloadLen: 57,
			},
			dir: gpuproto.ToRenderer,
		},
		{
			name: "transfer_reply_with_fd",
			hdr: gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpTransfer,
				Flags:      gpuproto.FlagReply | gpuproto.FlagFD,
				Seq:        1,
				CtxID:      2,
				PayloadLen: 0,
				Status:     gpuproto.StatusOK,
			},
			dir: gpuproto.FromRenderer,
		},
		{
			name: "res_create_error_reply_with_fd",
			hdr: gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpResCreate,
				Flags:      gpuproto.FlagReply | gpuproto.FlagFD,
				Seq:        1,
				CtxID:      2,
				PayloadLen: 0,
				Status:     gpuproto.StatusInvalid,
			},
			dir: gpuproto.FromRenderer,
		},
	}
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			raw := gpuproto.AppendHeader(nil, tc.hdr)
			if _, err := gpuproto.ParseHeader(raw, tc.dir); !errors.Is(err, gpuproto.ErrMalformed) {
				t.Fatalf("ParseHeader(%s) error = %v, want wrapping ErrMalformed", tc.name, err)
			}
		})
	}
}

func TestModeHelpers(t *testing.T) {
	cases := []struct {
		mode        gpuproto.Mode
		wantString  string
		wantValid   bool
		wantCapsets []uint32
		wantPrimary uint32
	}{
		{gpuproto.Mode(0), "MODE(0)", false, nil, 0},
		{gpuproto.ModeVenus, "venus", true, []uint32{gpuproto.CapsetVenus}, gpuproto.CapsetVenus},
		{gpuproto.ModeVirgl, "virgl", true, []uint32{gpuproto.CapsetVirgl, gpuproto.CapsetVirgl2}, gpuproto.CapsetVirgl2},
		{gpuproto.Mode(3), "MODE(3)", false, nil, 0},
	}
	for _, tc := range cases {
		if got := tc.mode.String(); got != tc.wantString {
			t.Errorf("Mode(%d).String() = %q, want %q", tc.mode, got, tc.wantString)
		}
		if got := tc.mode.Valid(); got != tc.wantValid {
			t.Errorf("Mode(%d).Valid() = %v, want %v", tc.mode, got, tc.wantValid)
		}
		gotCaps := tc.mode.Capsets()
		if !slices.Equal(gotCaps, tc.wantCapsets) || (gotCaps == nil) != (tc.wantCapsets == nil) {
			t.Errorf("Mode(%d).Capsets() = %v, want %v", tc.mode, gotCaps, tc.wantCapsets)
		}
		if len(gotCaps) > 0 {
			gotCaps[0] = 99
			if !slices.Equal(tc.mode.Capsets(), tc.wantCapsets) {
				t.Errorf("Mode(%d).Capsets() aliased internal storage after caller mutation", tc.mode)
			}
		}
		if got := tc.mode.PrimaryCapset(); got != tc.wantPrimary {
			t.Errorf("Mode(%d).PrimaryCapset() = %d, want %d", tc.mode, got, tc.wantPrimary)
		}
	}
}
