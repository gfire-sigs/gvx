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
	"testing"

	"z.gfire.dev/gvx/internal/gpurender/gpurendertest"
	"z.gfire.dev/gvx/pkg/hostarch"
)

func TestRendererCapsetThroughDevice(t *testing.T) {
	client := gpurendertest.New(t)
	wantCapset, ok := client.Capset(virtgpuCapsetVenus, 0)
	if !ok || len(wantCapset) < 4 {
		t.Fatalf("client.Capset(venus, 0) = (len %d, %v), want >= 4 bytes", len(wantCapset), ok)
	}
	if ver := binary.LittleEndian.Uint32(wantCapset[:4]); ver != 1 {
		t.Fatalf("venus wire_format_version = %d, want 1", ver)
	}

	node := newTestNode(t, client)
	fd := node.open(t)

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		bufAddr    = hostarch.Addr(0x2000)
	)
	mem.put(t, structAddr, virtgpuGetCaps{
		CapSetID:  virtgpuCapsetVenus,
		CapSetVer: 0,
		Addr:      uint64(bufAddr),
		Size:      uint32(len(wantCapset)),
	})
	if err := node.ioctl(fd, cmdVirtgpuGetCaps, mem, structAddr); err != nil {
		fd.DecRef(node.ctx)
		t.Fatalf("GET_CAPS: %v", err)
	}
	if got := mem.readBytes(bufAddr, len(wantCapset)); !bytes.Equal(got, wantCapset) {
		fd.DecRef(node.ctx)
		t.Fatalf("GET_CAPS bytes differ from client.Capset")
	}

	putContextInit(t, mem, structAddr, bufAddr, mesaVenusParams())
	if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, structAddr); err != nil {
		fd.DecRef(node.ctx)
		t.Fatalf("CONTEXT_INIT: %v", err)
	}
	fd.DecRef(node.ctx)

	for i := range 8 {
		nextFD := node.open(t)
		putContextInit(t, mem, structAddr, bufAddr, mesaVenusParams())
		if err := node.ioctl(nextFD, cmdVirtgpuContextInit, mem, structAddr); err != nil {
			nextFD.DecRef(node.ctx)
			t.Fatalf("CONTEXT_INIT round %d: %v", i+1, err)
		}
		nextFD.DecRef(node.ctx)
	}
}

func TestVirglCapsetThroughDevice(t *testing.T) {
	client := gpurendertest.NewVirgl(t)
	wantCapset, ok := client.Capset(virtgpuCapsetVirgl2, 0)
	if !ok || len(wantCapset) < 4 {
		t.Fatalf("client.Capset(virgl2, 0) = (len %d, %v), want >= 4 bytes", len(wantCapset), ok)
	}
	if ver := binary.LittleEndian.Uint32(wantCapset[:4]); ver != 2 {
		t.Fatalf("virgl2 capset version = %d, want 2", ver)
	}

	node := newTestNode(t, client)
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		bufAddr    = hostarch.Addr(0x2000)
	)
	mem.put(t, structAddr, virtgpuGetCaps{
		CapSetID:  virtgpuCapsetVirgl2,
		CapSetVer: 0,
		Addr:      uint64(bufAddr),
		Size:      uint32(len(wantCapset)),
	})
	if err := node.ioctl(fd, cmdVirtgpuGetCaps, mem, structAddr); err != nil {
		t.Fatalf("GET_CAPS(2, 0): %v", err)
	}
	got := mem.readBytes(bufAddr, len(wantCapset))
	if !bytes.Equal(got, wantCapset) {
		t.Fatalf("GET_CAPS(2, 0) bytes differ from client.Capset")
	}
	if ver := binary.LittleEndian.Uint32(got[:4]); ver != 2 {
		t.Fatalf("GET_CAPS(2, 0) first word = %d, want 2", ver)
	}
}
