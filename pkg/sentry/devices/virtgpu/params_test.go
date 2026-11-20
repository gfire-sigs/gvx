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
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
)

func TestParamsGetParam(t *testing.T) {
	node := newTestNode(t, newFakeRenderer())
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		valAddr    = hostarch.Addr(0x2000)
	)

	cases := []struct {
		name  string
		param uint64
		want  uint32
	}{
		{"3D_FEATURES", virtgpuParam3DFeatures, 1},
		{"CAPSET_QUERY_FIX", virtgpuParamCapsetQueryFix, 1},
		{"RESOURCE_BLOB", virtgpuParamResourceBlob, 1},
		{"HOST_VISIBLE", virtgpuParamHostVisible, 1},
		{"CROSS_DEVICE", virtgpuParamCrossDevice, 0},
		{"CONTEXT_INIT", virtgpuParamContextInit, 1},
		{"SUPPORTED_CAPSET_IDs", virtgpuParamSupportedCapsetIDs, 1 << virtgpuCapsetVenus},
		{"EXPLICIT_DEBUG_NAME", virtgpuParamExplicitDebugName, 1},
		{"BLOB_ALIGNMENT", virtgpuParamBlobAlignment, blobAlignment},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mem.writeBytes(valAddr, makeFilled(8, 0xff))
			mem.put(t, structAddr, virtgpuGetparam{Param: tc.param, Value: uint64(valAddr)})
			if err := node.ioctl(fd, cmdVirtgpuGetparam, mem, structAddr); err != nil {
				t.Fatalf("GETPARAM(%d): %v", tc.param, err)
			}
			raw := mem.readBytes(valAddr, 8)
			got := binary.LittleEndian.Uint32(raw[:4])
			if got != tc.want {
				t.Errorf("GETPARAM(%d) low 4 bytes = %#x, want %#x", tc.param, got, tc.want)
			}
			if !bytes.Equal(raw[4:8], []byte{0xff, 0xff, 0xff, 0xff}) {
				t.Errorf("GETPARAM(%d) high 4 bytes = %x, want ffffffff (must write 4 bytes)", tc.param, raw[4:8])
			}
		})
	}

	for _, bad := range []uint64{0, 10} {
		mem.put(t, structAddr, virtgpuGetparam{Param: bad, Value: uint64(valAddr)})
		if err := node.ioctl(fd, cmdVirtgpuGetparam, mem, structAddr); !linuxerr.Equals(linuxerr.EINVAL, err) {
			t.Errorf("GETPARAM(%d): got %v, want EINVAL", bad, err)
		}
	}

	mem.put(t, structAddr, virtgpuGetparam{Param: virtgpuParam3DFeatures, Value: uint64(badGuestAddr)})
	if err := node.ioctl(fd, cmdVirtgpuGetparam, mem, structAddr); !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Errorf("GETPARAM with bad pointer: got %v, want EFAULT", err)
	}
}

func TestParamsGetCaps(t *testing.T) {
	fake := newFakeRenderer()
	wantCapset, _ := fake.Capset(virtgpuCapsetVenus, 0)
	node := newTestNode(t, fake)
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		bufAddr    = hostarch.Addr(0x2000)
	)

	// Size 64 copies 64 bytes and leaves byte 64 untouched.
	mem.writeBytes(bufAddr, makeFilled(256, 0xee))
	mem.put(t, structAddr, virtgpuGetCaps{
		CapSetID:  virtgpuCapsetVenus,
		CapSetVer: 0,
		Addr:      uint64(bufAddr),
		Size:      64,
	})
	if err := node.ioctl(fd, cmdVirtgpuGetCaps, mem, structAddr); err != nil {
		t.Fatalf("GET_CAPS(64): %v", err)
	}
	if !bytes.Equal(mem.readBytes(bufAddr, 64), wantCapset[:64]) {
		t.Errorf("GET_CAPS(64): copied bytes differ from capset prefix")
	}
	if got := mem.readBytes(bufAddr+64, 1)[0]; got != 0xee {
		t.Errorf("GET_CAPS(64): byte 64 = %#x, want 0xee", got)
	}

	// Size 4096 copies all 160 bytes.
	mem.writeBytes(bufAddr, makeFilled(256, 0xdd))
	mem.put(t, structAddr, virtgpuGetCaps{
		CapSetID:  virtgpuCapsetVenus,
		CapSetVer: 0,
		Addr:      uint64(bufAddr),
		Size:      4096,
	})
	if err := node.ioctl(fd, cmdVirtgpuGetCaps, mem, structAddr); err != nil {
		t.Fatalf("GET_CAPS(4096): %v", err)
	}
	if !bytes.Equal(mem.readBytes(bufAddr, len(wantCapset)), wantCapset) {
		t.Errorf("GET_CAPS(4096): copied bytes differ from full capset")
	}
	if got := mem.readBytes(bufAddr+hostarch.Addr(len(wantCapset)), 1)[0]; got != 0xdd {
		t.Errorf("GET_CAPS(4096): byte %d = %#x, want 0xdd", len(wantCapset), got)
	}

	// Invalid size, unknown capset ID, unknown version.
	badCases := []struct {
		name string
		req  virtgpuGetCaps
		want error
	}{
		{"size 0", virtgpuGetCaps{CapSetID: virtgpuCapsetVenus, CapSetVer: 0, Addr: uint64(bufAddr), Size: 0}, linuxerr.EINVAL},
		{"unknown id 1", virtgpuGetCaps{CapSetID: 1, CapSetVer: 0, Addr: uint64(bufAddr), Size: 64}, linuxerr.EINVAL},
		{"unknown version 1", virtgpuGetCaps{CapSetID: virtgpuCapsetVenus, CapSetVer: 1, Addr: uint64(bufAddr), Size: 64}, linuxerr.EINVAL},
		{"bad addr", virtgpuGetCaps{CapSetID: virtgpuCapsetVenus, CapSetVer: 0, Addr: uint64(badGuestAddr), Size: 64}, linuxerr.EFAULT},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			mem.put(t, structAddr, tc.req)
			if err := node.ioctl(fd, cmdVirtgpuGetCaps, mem, structAddr); !errors.Is(err, tc.want) {
				t.Errorf("GET_CAPS(%s): got %v, want %v", tc.name, err, tc.want)
			}
		})
	}

	// Cached capset remains readable after renderer loss.
	fake.emitRendererLost(errors.New("renderer exited"))
	mem.writeBytes(bufAddr, makeFilled(len(wantCapset), 0x00))
	mem.put(t, structAddr, virtgpuGetCaps{
		CapSetID:  virtgpuCapsetVenus,
		CapSetVer: 0,
		Addr:      uint64(bufAddr),
		Size:      uint32(len(wantCapset)),
	})
	if err := node.ioctl(fd, cmdVirtgpuGetCaps, mem, structAddr); err != nil {
		t.Fatalf("GET_CAPS after renderer loss: %v", err)
	}
	if !bytes.Equal(mem.readBytes(bufAddr, len(wantCapset)), wantCapset) {
		t.Errorf("GET_CAPS after renderer loss: copied bytes differ from capset")
	}
}
