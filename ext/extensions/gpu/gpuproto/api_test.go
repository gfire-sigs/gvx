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
	"errors"
	"fmt"
	"strings"
	"testing"

	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
	"z.gfire.dev/gvx/pkg/abi/linux/errno"
)

func TestStatusErrnoMatchesLinux(t *testing.T) {
	cases := []struct {
		status gpuproto.Status
		want   uint32
	}{
		{gpuproto.StatusOK, 0},
		{gpuproto.StatusIO, uint32(errno.EIO)},
		{gpuproto.StatusNoMemory, uint32(errno.ENOMEM)},
		{gpuproto.StatusExists, uint32(errno.EEXIST)},
		{gpuproto.StatusInvalid, uint32(errno.EINVAL)},
		{gpuproto.StatusNoSpace, uint32(errno.ENOSPC)},
		{gpuproto.StatusNotSupported, uint32(errno.EOPNOTSUPP)},
	}
	for _, tc := range cases {
		if got := tc.status.Errno(); got != tc.want {
			t.Errorf("%s.Errno() = %d, want %d", tc.status, got, tc.want)
		}
	}
}

func TestStatusErrorUnwrapsWithAs(t *testing.T) {
	wrapped := fmt.Errorf("x: %w", &gpuproto.StatusError{
		Op:     gpuproto.OpCtxCreate,
		Status: gpuproto.StatusNoSpace,
	})
	var se *gpuproto.StatusError
	if !errors.As(wrapped, &se) {
		t.Fatalf("errors.As(%v, *StatusError) = false, want true", wrapped)
	}
	if got := se.Errno(); got != uint32(errno.ENOSPC) {
		t.Errorf("StatusError.Errno() = %d, want %d", got, uint32(errno.ENOSPC))
	}
	msg := se.Error()
	if !strings.Contains(msg, "CTX_CREATE") || !strings.Contains(msg, "ENOSPC") {
		t.Errorf("StatusError.Error() = %q, want CTX_CREATE and ENOSPC", msg)
	}
}

func TestBlobCreateValidate(t *testing.T) {
	valid := func() gpuproto.BlobCreate {
		return gpuproto.BlobCreate{
			CtxID:     1,
			ResID:     2,
			BlobMem:   gpuproto.BlobMemHost3D,
			BlobFlags: gpuproto.BlobFlagMappable,
			BlobID:    0,
			Size:      gpuproto.HostBlobAlign,
		}
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid BlobCreate.Validate() = %v, want nil", err)
	}

	badCases := []struct {
		name   string
		mutate func(*gpuproto.BlobCreate)
	}{
		{"ctx_id_0", func(b *gpuproto.BlobCreate) { b.CtxID = 0 }},
		{"res_id_0", func(b *gpuproto.BlobCreate) { b.ResID = 0 }},
		{"blob_mem_1", func(b *gpuproto.BlobCreate) { b.BlobMem = 1 }},
		{"flag_bit_8", func(b *gpuproto.BlobCreate) { b.BlobFlags = 8 }},
		{"size_0", func(b *gpuproto.BlobCreate) { b.Size = 0 }},
		{"size_above_max", func(b *gpuproto.BlobCreate) { b.Size = gpuproto.MaxBlobBytes + 1 }},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			b := valid()
			tc.mutate(&b)
			err := b.Validate()
			var se *gpuproto.StatusError
			if !errors.As(err, &se) || se.Op != gpuproto.OpBlobCreate || se.Status != gpuproto.StatusInvalid {
				t.Fatalf("Validate() = %v, want *StatusError{OpBlobCreate, StatusInvalid}", err)
			}
		})
	}
}

func TestFenceValidate(t *testing.T) {
	if err := (gpuproto.Fence{RingIdx: 63, ID: 1}).Validate(); err != nil {
		t.Fatalf("valid Fence.Validate() = %v, want nil", err)
	}
	for _, f := range []gpuproto.Fence{{RingIdx: 64, ID: 1}, {RingIdx: 0, ID: 0}} {
		err := f.Validate()
		var se *gpuproto.StatusError
		if !errors.As(err, &se) || se.Op != gpuproto.OpSubmit || se.Status != gpuproto.StatusInvalid {
			t.Fatalf("Fence(%+v).Validate() = %v, want *StatusError{OpSubmit, StatusInvalid}", f, err)
		}
	}
}

func TestResourceCreateValidate(t *testing.T) {
	valid := func() gpuproto.ResourceCreate {
		return gpuproto.ResourceCreate{
			CtxID:     1,
			ResID:     2,
			Target:    2,
			Format:    67,
			Bind:      10,
			Width:     256,
			Height:    128,
			Depth:     1,
			ArraySize: 1,
			LastLevel: 0,
			NrSamples: 0,
			Flags:     0,
			Size:      gpuproto.HostBlobAlign,
		}
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid ResourceCreate.Validate() = %v, want nil", err)
	}
	for _, size := range []uint64{1, gpuproto.MaxBlobBytes} {
		r := valid()
		r.Size = size
		if err := r.Validate(); err != nil {
			t.Fatalf("ResourceCreate(Size=%d).Validate() = %v, want nil", size, err)
		}
	}

	gotReq := valid().Request()
	wantReq := gpuproto.ResCreateRequest{
		ResID:     2,
		Target:    2,
		Format:    67,
		Bind:      10,
		Width:     256,
		Height:    128,
		Depth:     1,
		ArraySize: 1,
		LastLevel: 0,
		NrSamples: 0,
		Flags:     0,
		Reserved:  0,
		Size:      gpuproto.HostBlobAlign,
	}
	if gotReq != wantReq {
		t.Fatalf("ResourceCreate.Request() = %+v, want %+v", gotReq, wantReq)
	}

	badCases := []struct {
		name   string
		mutate func(*gpuproto.ResourceCreate)
	}{
		{"ctx_id_0", func(r *gpuproto.ResourceCreate) { r.CtxID = 0 }},
		{"res_id_0", func(r *gpuproto.ResourceCreate) { r.ResID = 0 }},
		{"size_0", func(r *gpuproto.ResourceCreate) { r.Size = 0 }},
		{"size_above_max", func(r *gpuproto.ResourceCreate) { r.Size = gpuproto.MaxBlobBytes + 1 }},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			r := valid()
			tc.mutate(&r)
			err := r.Validate()
			var se *gpuproto.StatusError
			if !errors.As(err, &se) || se.Op != gpuproto.OpResCreate || se.Status != gpuproto.StatusInvalid {
				t.Fatalf("Validate() = %v, want *StatusError{OpResCreate, StatusInvalid}", err)
			}
		})
	}
}

func TestTransferValidate(t *testing.T) {
	valid := func() gpuproto.Transfer {
		return gpuproto.Transfer{
			CtxID:       1,
			ResID:       2,
			Direction:   gpuproto.TransferToHost,
			Level:       1,
			Stride:      1024,
			LayerStride: 4096,
			Box:         gpuproto.Box{X: 3, Y: 4, Z: 5, W: 64, H: 32, D: 1},
			Offset:      8192,
		}
	}
	for _, dir := range []uint32{gpuproto.TransferToHost, gpuproto.TransferFromHost} {
		tr := valid()
		tr.Direction = dir
		if err := tr.Validate(); err != nil {
			t.Fatalf("Transfer(Direction=%d).Validate() = %v, want nil", dir, err)
		}
	}

	gotReq := valid().Request()
	wantReq := gpuproto.TransferRequest{
		ResID:       2,
		Direction:   gpuproto.TransferToHost,
		Level:       1,
		Stride:      1024,
		LayerStride: 4096,
		BoxX:        3,
		BoxY:        4,
		BoxZ:        5,
		BoxW:        64,
		BoxH:        32,
		BoxD:        1,
		Reserved:    0,
		Offset:      8192,
	}
	if gotReq != wantReq {
		t.Fatalf("Transfer.Request() = %+v, want %+v", gotReq, wantReq)
	}

	badCases := []struct {
		name   string
		mutate func(*gpuproto.Transfer)
	}{
		{"ctx_id_0", func(tr *gpuproto.Transfer) { tr.CtxID = 0 }},
		{"res_id_0", func(tr *gpuproto.Transfer) { tr.ResID = 0 }},
		{"direction_0", func(tr *gpuproto.Transfer) { tr.Direction = 0 }},
		{"direction_3", func(tr *gpuproto.Transfer) { tr.Direction = 3 }},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			tr := valid()
			tc.mutate(&tr)
			err := tr.Validate()
			var se *gpuproto.StatusError
			if !errors.As(err, &se) || se.Op != gpuproto.OpTransfer || se.Status != gpuproto.StatusInvalid {
				t.Fatalf("Validate() = %v, want *StatusError{OpTransfer, StatusInvalid}", err)
			}
		})
	}
}
