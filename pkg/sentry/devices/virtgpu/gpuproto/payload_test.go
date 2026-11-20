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
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

func checkFixedPayload[T interface {
	gpuproto.HelloRequest | gpuproto.HelloReply | gpuproto.CapsetInfo | gpuproto.GetCapsetRequest |
		gpuproto.CtxCreateRequest | gpuproto.BlobCreateRequest | gpuproto.BlobCreateReply |
		gpuproto.ResUnrefRequest | gpuproto.SubmitRequest | gpuproto.FenceDoneEvent | gpuproto.CtxLostEvent |
		gpuproto.TestConfineReply
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

	checkFixedPayload(t, "HelloRequest", 8, gpuproto.HelloRequest{Version: 1, Reserved: 2})
	checkFixedPayload(t, "HelloReply", 64, gpuproto.HelloReply{Version: 1, NumCapsets: 2, Build: build})
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

func TestHelloReplyRoundTrip(t *testing.T) {
	wantCaps := []gpuproto.CapsetInfo{
		{ID: gpuproto.CapsetVenus, MaxVersion: 1, MaxSize: 1024},
	}
	raw, err := gpuproto.AppendHelloReply(nil, "gvx-gpu-renderer test", wantCaps)
	if err != nil {
		t.Fatalf("AppendHelloReply: %v", err)
	}
	ver, build, gotCaps, err := gpuproto.DecodeHelloReply(raw)
	if err != nil {
		t.Fatalf("DecodeHelloReply: %v", err)
	}
	if ver != gpuproto.Version {
		t.Errorf("version = %d, want %d", ver, gpuproto.Version)
	}
	if build != "gvx-gpu-renderer test" {
		t.Errorf("build = %q, want %q", build, "gvx-gpu-renderer test")
	}
	if !slices.Equal(gotCaps, wantCaps) {
		t.Errorf("caps = %+v, want %+v", gotCaps, wantCaps)
	}

	rawBadCount := gpuproto.AppendPayload(nil, gpuproto.HelloReply{Version: gpuproto.Version, NumCapsets: gpuproto.MaxCapsets + 1})
	for range gpuproto.MaxCapsets + 1 {
		rawBadCount = gpuproto.AppendPayload(rawBadCount, wantCaps[0])
	}
	if _, _, _, err := gpuproto.DecodeHelloReply(rawBadCount); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeHelloReply(num_capsets=9) error = %v, want wrapping ErrMalformed", err)
	}

	if _, _, _, err := gpuproto.DecodeHelloReply(raw[:len(raw)-1]); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("DecodeHelloReply(length off by one) error = %v, want wrapping ErrMalformed", err)
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
			b, err := gpuproto.AppendHelloReply(nil, "ok", []gpuproto.CapsetInfo{tc.info})
			if err != nil {
				t.Fatalf("AppendHelloReply: %v", err)
			}
			if _, _, _, err := gpuproto.DecodeHelloReply(b); !errors.Is(err, gpuproto.ErrMalformed) {
				t.Fatalf("DecodeHelloReply(%s) error = %v, want wrapping ErrMalformed", tc.name, err)
			}
		})
	}

	rawControl, err := gpuproto.AppendHelloReply(nil, "a\x01b", nil)
	if err != nil {
		t.Fatalf("AppendHelloReply(control byte): %v", err)
	}
	_, build, _, err = gpuproto.DecodeHelloReply(rawControl)
	if err != nil {
		t.Fatalf("DecodeHelloReply(control byte): %v", err)
	}
	if build != "a?b" {
		t.Fatalf("sanitized build = %q, want %q", build, "a?b")
	}

	tooManyCaps := make([]gpuproto.CapsetInfo, gpuproto.MaxCapsets+1)
	if _, err := gpuproto.AppendHelloReply(nil, "ok", tooManyCaps); !errors.Is(err, gpuproto.ErrMalformed) {
		t.Fatalf("AppendHelloReply(9 capsets) error = %v, want wrapping ErrMalformed", err)
	}
}
