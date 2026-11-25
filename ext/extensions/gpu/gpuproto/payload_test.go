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
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
)

func checkFixedPayload[T interface {
	gpuproto.HelloRequest | gpuproto.HelloReply | gpuproto.CapsetInfo | gpuproto.GetCapsetRequest |
		gpuproto.CtxCreateRequest | gpuproto.BlobCreateRequest | gpuproto.BlobCreateReply |
		gpuproto.ResUnrefRequest | gpuproto.SubmitRequest | gpuproto.FenceDoneEvent | gpuproto.CtxLostEvent |
		gpuproto.TestConfineReply | gpuproto.ResCreateRequest | gpuproto.ResCreateReply | gpuproto.TransferRequest
	comparable
}](t *testing.T, name string, wantSize int, v T) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		if got := gpuproto.PayloadSize[T](); got != wantSize {
			t.Fatalf("PayloadSize[%s]() = %d, want %d", name, got, wantSize)
		}
		raw := gpuproto.AppendPayload(nil, v)
		if len(raw) != wantSize {
			t.Fatalf("AppendPayload length = %d, want %d", len(raw), wantSize)
		}
		got, err := gpuproto.DecodePayload[T](raw)
		if err != nil {
			t.Fatalf("DecodePayload: %v", err)
		}
		if got != v {
			t.Fatalf("DecodePayload = %+v, want %+v", got, v)
		}
		if _, err := gpuproto.DecodePayload[T](raw[:len(raw)-1]); !errors.Is(err, gpuproto.ErrMalformed) {
			t.Fatalf("DecodePayload(short) error = %v, want wrapping ErrMalformed", err)
		}
		if _, err := gpuproto.DecodePayload[T](append(slices.Clone(raw), 0)); !errors.Is(err, gpuproto.ErrMalformed) {
			t.Fatalf("DecodePayload(long) error = %v, want wrapping ErrMalformed", err)
		}
	})
}

func TestPayloadRoundTrip(t *testing.T) {
	var build [56]byte
	for i := range build {
		build[i] = byte(i + 1)
	}

	checkFixedPayload(t, "HelloRequest", 8, gpuproto.HelloRequest{Version: 2, Mode: gpuproto.ModeVirgl})
	checkFixedPayload(t, "HelloReply", 72, gpuproto.HelloReply{Version: 2, NumCapsets: 2, Mode: gpuproto.ModeVirgl, Build: build})
	checkFixedPayload(t, "CapsetInfo", 16, gpuproto.CapsetInfo{ID: 4, MaxVersion: 1, MaxSize: 512, Reserved: 9})
	checkFixedPayload(t, "GetCapsetRequest", 8, gpuproto.GetCapsetRequest{ID: 4, Version: 1})
	checkFixedPayload(t, "CtxCreateRequest", 8, gpuproto.CtxCreateRequest{CapsetID: 4, NameLen: 12})
	checkFixedPayload(t, "BlobCreateRequest", 32, gpuproto.BlobCreateRequest{
		ResID: 1, BlobMem: 2, BlobFlags: 3, Reserved: 4, BlobID: 5, Size: 6,
	})
	checkFixedPayload(t, "BlobCreateReply", 16, gpuproto.BlobCreateReply{HostSize: 0x4000, MapInfo: 1, FDType: 3})
	checkFixedPayload(t, "ResUnrefRequest", 8, gpuproto.ResUnrefRequest{ResID: 7, Reserved: 8})
	checkFixedPayload(t, "SubmitRequest", 24, gpuproto.SubmitRequest{
		CmdLen: 16, Flags: 1, RingIdx: 2, Reserved: 3, FenceID: 4,
	})
	checkFixedPayload(t, "FenceDoneEvent", 16, gpuproto.FenceDoneEvent{RingIdx: 3, Reserved: 4, FenceID: 5})
	checkFixedPayload(t, "CtxLostEvent", 8, gpuproto.CtxLostEvent{Reason: 1, Reserved: 2})
	checkFixedPayload(t, "TestConfineReply", 12, gpuproto.TestConfineReply{
		Checks: gpuproto.ConfineChecks,
		Results: [8]uint8{
			uint8(gpuproto.ConfineDenied),
			uint8(gpuproto.ConfineDenied),
			uint8(gpuproto.ConfineDenied),
			uint8(gpuproto.ConfineDenied),
			uint8(gpuproto.ConfineDenied),
		},
	})
	checkFixedPayload(t, "ResCreateRequest", 56, gpuproto.ResCreateRequest{
		ResID: 1, Target: 2, Format: 3, Bind: 4, Width: 5, Height: 6, Depth: 7,
		ArraySize: 8, LastLevel: 9, NrSamples: 10, Flags: 11, Reserved: 12, Size: 0x10000,
	})
	checkFixedPayload(t, "ResCreateReply", 16, gpuproto.ResCreateReply{
		HostSize: 0x10000, FDType: gpuproto.FDTypeShm, Reserved: 0,
	})
	checkFixedPayload(t, "TransferRequest", 56, gpuproto.TransferRequest{
		ResID: 1, Direction: gpuproto.TransferToHost, Level: 2, Stride: 3, LayerStride: 4,
		BoxX: 5, BoxY: 6, BoxZ: 7, BoxW: 8, BoxH: 9, BoxD: 10, Reserved: 11, Offset: 12,
	})
}

func TestPayloadLittleEndian(t *testing.T) {
	got := gpuproto.AppendPayload(nil, gpuproto.FenceDoneEvent{
		RingIdx: 1,
		FenceID: 0x0102030405060708,
	})
	want := []byte{
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("AppendPayload(FenceDoneEvent) = % x, want % x", got, want)
	}
}

func TestCtxCreateRoundTrip(t *testing.T) {
	name64 := strings.Repeat("a", gpuproto.MaxContextNameBytes)
	raw, err := gpuproto.AppendCtxCreate(nil, gpuproto.CapsetVenus, name64)
	if err != nil {
		t.Fatalf("AppendCtxCreate(64): %v", err)
	}
	capID, gotName, err := gpuproto.DecodeCtxCreate(raw)
	if err != nil {
		t.Fatalf("DecodeCtxCreate(64): %v", err)
	}
	if capID != gpuproto.CapsetVenus || gotName != name64 {
		t.Fatalf("DecodeCtxCreate(64) = (%d, %q), want (%d, %q)", capID, gotName, gpuproto.CapsetVenus, name64)
	}

	rawEmpty, err := gpuproto.AppendCtxCreate(nil, gpuproto.CapsetVenus, "")
	if err != nil {
		t.Fatalf("AppendCtxCreate(empty): %v", err)
	}
	capID, gotName, err = gpuproto.DecodeCtxCreate(rawEmpty)
	if err != nil {
		t.Fatalf("DecodeCtxCreate(empty): %v", err)
	}
	if capID != gpuproto.CapsetVenus || gotName != "" {
		t.Fatalf("DecodeCtxCreate(empty) = (%d, %q), want (%d, %q)", capID, gotName, gpuproto.CapsetVenus, "")
	}

	_, err = gpuproto.AppendCtxCreate(nil, gpuproto.CapsetVenus, strings.Repeat("a", gpuproto.MaxContextNameBytes+1))
	var se *gpuproto.StatusError
	if !errors.As(err, &se) || se.Op != gpuproto.OpCtxCreate || se.Status != gpuproto.StatusInvalid {
		t.Fatalf("AppendCtxCreate(65) error = %v, want *StatusError{OpCtxCreate, StatusInvalid}", err)
	}

	overName := gpuproto.AppendPayload(nil, gpuproto.CtxCreateRequest{
		CapsetID: gpuproto.CapsetVenus,
		NameLen:  gpuproto.MaxContextNameBytes + 1,
	})
	overName = append(overName, bytes.Repeat([]byte("a"), gpuproto.MaxContextNameBytes+1)...)
	if _, _, err := gpuproto.DecodeCtxCreate(overName); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeCtxCreate(name_len=65) error = %v, want wrapping ErrMalformed", err)
	}

	if _, _, err := gpuproto.DecodeCtxCreate(append(slices.Clone(raw), 'x')); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeCtxCreate(extra byte) error = %v, want wrapping ErrMalformed", err)
	}
}

func TestSubmitRoundTrip(t *testing.T) {
	cmd := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantFence := gpuproto.Fence{RingIdx: 63, ID: 9}

	rawWithFence, err := gpuproto.AppendSubmit(nil, cmd, &wantFence)
	if err != nil {
		t.Fatalf("AppendSubmit(with fence): %v", err)
	}
	gotCmd, gotFence, err := gpuproto.DecodeSubmit(rawWithFence)
	if err != nil {
		t.Fatalf("DecodeSubmit(with fence): %v", err)
	}
	if !bytes.Equal(gotCmd, cmd) {
		t.Fatalf("cmd = % x, want % x", gotCmd, cmd)
	}
	if gotFence == nil || *gotFence != wantFence {
		t.Fatalf("fence = %+v, want %+v", gotFence, wantFence)
	}

	rawNoFence, err := gpuproto.AppendSubmit(nil, cmd, nil)
	if err != nil {
		t.Fatalf("AppendSubmit(no fence): %v", err)
	}
	gotCmd, gotFence, err = gpuproto.DecodeSubmit(rawNoFence)
	if err != nil {
		t.Fatalf("DecodeSubmit(no fence): %v", err)
	}
	if !bytes.Equal(gotCmd, cmd) || gotFence != nil {
		t.Fatalf("DecodeSubmit(no fence) = (% x, %+v), want (% x, nil)", gotCmd, gotFence, cmd)
	}

	rejectCases := []struct {
		name  string
		cmd   []byte
		fence *gpuproto.Fence
	}{
		{"unaligned_6_bytes", make([]byte, 6), nil},
		{"too_large", make([]byte, gpuproto.MaxSubmitBytes+4), nil},
		{"fence_ring_64", cmd, &gpuproto.Fence{RingIdx: gpuproto.MaxRings, ID: 1}},
		{"fence_id_0", cmd, &gpuproto.Fence{RingIdx: 0, ID: 0}},
	}
	for _, tc := range rejectCases {
		t.Run("append_reject/"+tc.name, func(t *testing.T) {
			_, err := gpuproto.AppendSubmit(nil, tc.cmd, tc.fence)
			var se *gpuproto.StatusError
			if !errors.As(err, &se) || se.Op != gpuproto.OpSubmit || se.Status != gpuproto.StatusInvalid {
				t.Fatalf("AppendSubmit error = %v, want *StatusError{OpSubmit, StatusInvalid}", err)
			}
		})
	}

	badLen := gpuproto.AppendPayload(nil, gpuproto.SubmitRequest{CmdLen: 8})
	badLen = append(badLen, make([]byte, 12)...)
	if _, _, err := gpuproto.DecodeSubmit(badLen); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeSubmit(length mismatch) error = %v, want wrapping ErrMalformed", err)
	}

	badFlag := gpuproto.AppendPayload(nil, gpuproto.SubmitRequest{CmdLen: 4, Flags: 1 << 1})
	badFlag = append(badFlag, make([]byte, 4)...)
	if _, _, err := gpuproto.DecodeSubmit(badFlag); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeSubmit(unknown flag) error = %v, want wrapping ErrMalformed", err)
	}

	decodeRejectCases := []struct {
		name string
		raw  []byte
	}{
		{
			name: "unaligned_cmd_len",
			raw:  append(gpuproto.AppendPayload(nil, gpuproto.SubmitRequest{CmdLen: 6}), make([]byte, 6)...),
		},
		{
			name: "oversized_cmd_len",
			raw:  gpuproto.AppendPayload(nil, gpuproto.SubmitRequest{CmdLen: gpuproto.MaxSubmitBytes + 4}),
		},
		{
			name: "fence_ring_out_of_range",
			raw:  gpuproto.AppendPayload(nil, gpuproto.SubmitRequest{Flags: gpuproto.SubmitFlagFence, RingIdx: gpuproto.MaxRings, FenceID: 1}),
		},
		{
			name: "fence_id_zero",
			raw:  gpuproto.AppendPayload(nil, gpuproto.SubmitRequest{Flags: gpuproto.SubmitFlagFence, RingIdx: 0, FenceID: 0}),
		},
	}
	for _, tc := range decodeRejectCases {
		t.Run("decode_reject/"+tc.name, func(t *testing.T) {
			if _, _, err := gpuproto.DecodeSubmit(tc.raw); !errors.Is(err, gpuproto.ErrMalformed) {
				t.Fatalf("DecodeSubmit(%s) error = %v, want wrapping ErrMalformed", tc.name, err)
			}
		})
	}
}

func TestHelloRoundTrip(t *testing.T) {
	wantCaps := []gpuproto.CapsetInfo{
		{ID: gpuproto.CapsetVirgl, MaxVersion: 1, MaxSize: 308},
		{ID: gpuproto.CapsetVirgl2, MaxVersion: 2, MaxSize: 1408},
	}
	raw, err := gpuproto.AppendHello(nil, gpuproto.HelloInfo{
		Version: 99, // ignored by AppendHello
		Mode:    gpuproto.ModeVirgl,
		Build:   "gvx-gpu-renderer virgl",
		Caps:    wantCaps,
	})
	if err != nil {
		t.Fatalf("AppendHello: %v", err)
	}
	if wantLen := 72 + 16*len(wantCaps); len(raw) != wantLen {
		t.Fatalf("AppendHello length = %d, want %d", len(raw), wantLen)
	}

	got, err := gpuproto.DecodeHello(raw)
	if err != nil {
		t.Fatalf("DecodeHello: %v", err)
	}
	if got.Version != gpuproto.Version {
		t.Errorf("Version = %d, want %d", got.Version, gpuproto.Version)
	}
	if got.Mode != gpuproto.ModeVirgl {
		t.Errorf("Mode = %v, want %v", got.Mode, gpuproto.ModeVirgl)
	}
	if got.Build != "gvx-gpu-renderer virgl" {
		t.Errorf("Build = %q, want %q", got.Build, "gvx-gpu-renderer virgl")
	}
	if !slices.Equal(got.Caps, wantCaps) {
		t.Errorf("Caps = %+v, want %+v", got.Caps, wantCaps)
	}

	// Non-zero Reserved must be rejected.
	rawBadReserved := gpuproto.AppendPayload(nil, gpuproto.HelloReply{
		Version:    gpuproto.Version,
		NumCapsets: 0,
		Mode:       gpuproto.ModeVirgl,
		Reserved:   1,
	})
	if _, err := gpuproto.DecodeHello(rawBadReserved); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeHello(reserved=1) error = %v, want wrapping ErrMalformed", err)
	}

	// Length 72 + 16*n enforced.
	if _, err := gpuproto.DecodeHello(raw[:71]); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeHello(71 bytes) error = %v, want wrapping ErrMalformed", err)
	}
	if _, err := gpuproto.DecodeHello(raw[:len(raw)-1]); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeHello(short by 1) error = %v, want wrapping ErrMalformed", err)
	}
	if _, err := gpuproto.DecodeHello(append(slices.Clone(raw), 0)); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeHello(long by 1) error = %v, want wrapping ErrMalformed", err)
	}

	rawBadCount := gpuproto.AppendPayload(nil, gpuproto.HelloReply{Version: gpuproto.Version, NumCapsets: gpuproto.MaxCapsets + 1})
	for range gpuproto.MaxCapsets + 1 {
		rawBadCount = gpuproto.AppendPayload(rawBadCount, wantCaps[0])
	}
	if _, err := gpuproto.DecodeHello(rawBadCount); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeHello(num_capsets=9) error = %v, want wrapping ErrMalformed", err)
	}

	badCapCases := []struct {
		name string
		info gpuproto.CapsetInfo
	}{
		{"max_version_5", gpuproto.CapsetInfo{ID: gpuproto.CapsetVenus, MaxVersion: gpuproto.MaxCapsetVersion + 1, MaxSize: 64}},
		{"max_size_0", gpuproto.CapsetInfo{ID: gpuproto.CapsetVenus, MaxVersion: 1, MaxSize: 0}},
		{"max_size_4097", gpuproto.CapsetInfo{ID: gpuproto.CapsetVenus, MaxVersion: 1, MaxSize: gpuproto.MaxCapsetBytes + 1}},
	}
	for _, tc := range badCapCases {
		t.Run("bad_capset/"+tc.name, func(t *testing.T) {
			b, err := gpuproto.AppendHello(nil, gpuproto.HelloInfo{Mode: gpuproto.ModeVenus, Build: "ok", Caps: []gpuproto.CapsetInfo{tc.info}})
			if err != nil {
				t.Fatalf("AppendHello: %v", err)
			}
			if _, err := gpuproto.DecodeHello(b); !errors.Is(err, gpuproto.ErrMalformed) {
				t.Fatalf("DecodeHello(%s) error = %v, want wrapping ErrMalformed", tc.name, err)
			}
		})
	}

	rawControl, err := gpuproto.AppendHello(nil, gpuproto.HelloInfo{Mode: gpuproto.ModeVenus, Build: "a\x01b"})
	if err != nil {
		t.Fatalf("AppendHello(control byte): %v", err)
	}
	gotControl, err := gpuproto.DecodeHello(rawControl)
	if err != nil {
		t.Fatalf("DecodeHello(control byte): %v", err)
	}
	if gotControl.Build != "a?b" {
		t.Fatalf("sanitized build = %q, want %q", gotControl.Build, "a?b")
	}

	tooManyCaps := make([]gpuproto.CapsetInfo, gpuproto.MaxCapsets+1)
	if _, err := gpuproto.AppendHello(nil, gpuproto.HelloInfo{Mode: gpuproto.ModeVenus, Build: "ok", Caps: tooManyCaps}); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("AppendHello(9 capsets) error = %v, want wrapping ErrMalformed", err)
	}
}

func TestResCreateAndTransferLayout(t *testing.T) {
	if got := gpuproto.PayloadSize[gpuproto.ResCreateRequest](); got != 56 {
		t.Fatalf("PayloadSize[ResCreateRequest]() = %d, want 56", got)
	}
	if got := gpuproto.PayloadSize[gpuproto.ResCreateReply](); got != 16 {
		t.Fatalf("PayloadSize[ResCreateReply]() = %d, want 16", got)
	}
	if got := gpuproto.PayloadSize[gpuproto.TransferRequest](); got != 56 {
		t.Fatalf("PayloadSize[TransferRequest]() = %d, want 56", got)
	}

	resReq := gpuproto.ResCreateRequest{
		ResID:     0x01020304,
		Target:    0x05060708,
		Format:    0x090a0b0c,
		Bind:      0x0d0e0f10,
		Width:     0x11121314,
		Height:    0x15161718,
		Depth:     0x191a1b1c,
		ArraySize: 0x1d1e1f20,
		LastLevel: 0x21222324,
		NrSamples: 0x25262728,
		Flags:     0x292a2b2c,
		Reserved:  0x2d2e2f30,
		Size:      0x3132333435363738,
	}
	wantResReq := []byte{
		0x04, 0x03, 0x02, 0x01,
		0x08, 0x07, 0x06, 0x05,
		0x0c, 0x0b, 0x0a, 0x09,
		0x10, 0x0f, 0x0e, 0x0d,
		0x14, 0x13, 0x12, 0x11,
		0x18, 0x17, 0x16, 0x15,
		0x1c, 0x1b, 0x1a, 0x19,
		0x20, 0x1f, 0x1e, 0x1d,
		0x24, 0x23, 0x22, 0x21,
		0x28, 0x27, 0x26, 0x25,
		0x2c, 0x2b, 0x2a, 0x29,
		0x30, 0x2f, 0x2e, 0x2d,
		0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
	}
	buf := make([]byte, 56)
	if _, err := binary.Encode(buf, binary.LittleEndian, resReq); err != nil {
		t.Fatalf("binary.Encode(ResCreateRequest): %v", err)
	}
	if !bytes.Equal(buf, wantResReq) {
		t.Fatalf("ResCreateRequest bytes = % x, want % x", buf, wantResReq)
	}

	resRep := gpuproto.ResCreateReply{
		HostSize: 0x0102030405060708,
		FDType:   gpuproto.FDTypeShm,
		Reserved: 0x090a0b0c,
	}
	wantResRep := []byte{
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x03, 0x00, 0x00, 0x00,
		0x0c, 0x0b, 0x0a, 0x09,
	}
	repBuf := make([]byte, 16)
	if _, err := binary.Encode(repBuf, binary.LittleEndian, resRep); err != nil {
		t.Fatalf("binary.Encode(ResCreateReply): %v", err)
	}
	if !bytes.Equal(repBuf, wantResRep) {
		t.Fatalf("ResCreateReply bytes = % x, want % x", repBuf, wantResRep)
	}

	trReq := gpuproto.TransferRequest{
		ResID:       0x01020304,
		Direction:   gpuproto.TransferFromHost,
		Level:       0x05060708,
		Stride:      0x090a0b0c,
		LayerStride: 0x0d0e0f10,
		BoxX:        0x11121314,
		BoxY:        0x15161718,
		BoxZ:        0x191a1b1c,
		BoxW:        0x1d1e1f20,
		BoxH:        0x21222324,
		BoxD:        0x25262728,
		Reserved:    0x292a2b2c,
		Offset:      0x3132333435363738,
	}
	wantTrReq := []byte{
		0x04, 0x03, 0x02, 0x01,
		0x02, 0x00, 0x00, 0x00,
		0x08, 0x07, 0x06, 0x05,
		0x0c, 0x0b, 0x0a, 0x09,
		0x10, 0x0f, 0x0e, 0x0d,
		0x14, 0x13, 0x12, 0x11,
		0x18, 0x17, 0x16, 0x15,
		0x1c, 0x1b, 0x1a, 0x19,
		0x20, 0x1f, 0x1e, 0x1d,
		0x24, 0x23, 0x22, 0x21,
		0x28, 0x27, 0x26, 0x25,
		0x2c, 0x2b, 0x2a, 0x29,
		0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
	}
	trBuf := make([]byte, 56)
	if _, err := binary.Encode(trBuf, binary.LittleEndian, trReq); err != nil {
		t.Fatalf("binary.Encode(TransferRequest): %v", err)
	}
	if !bytes.Equal(trBuf, wantTrReq) {
		t.Fatalf("TransferRequest bytes = % x, want % x", trBuf, wantTrReq)
	}
}
