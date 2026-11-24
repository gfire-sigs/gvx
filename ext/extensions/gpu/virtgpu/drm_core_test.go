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
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
)

func TestDRMCoreVersionTwoCallProtocol(t *testing.T) {
	node := newTestNode(t, newFakeRenderer())
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		nameAddr   = hostarch.Addr(0x2000)
		dateAddr   = hostarch.Addr(0x2100)
		descAddr   = hostarch.Addr(0x2200)
	)

	// Call 1: query lengths with zero pointers and zero lengths.
	mem.put(t, structAddr, drmVersion{})
	if err := node.ioctl(fd, cmdVersion, mem, structAddr); err != nil {
		t.Fatalf("VERSION call 1: %v", err)
	}
	var v drmVersion
	mem.get(t, structAddr, &v)
	if v.VersionMajor != 0 || v.VersionMinor != 1 || v.VersionPatchlevel != 0 {
		t.Errorf("version = %d.%d.%d, want 0.1.0", v.VersionMajor, v.VersionMinor, v.VersionPatchlevel)
	}
	if v.NameLen != 10 || v.DateLen != 1 || v.DescLen != 10 {
		t.Errorf("lengths = (%d, %d, %d), want (10, 1, 10)", v.NameLen, v.DateLen, v.DescLen)
	}

	// Call 2: exact buffers with canary bytes immediately past each buffer.
	mem.writeBytes(nameAddr, makeFilled(16, 0xaa))
	mem.writeBytes(dateAddr, makeFilled(16, 0xbb))
	mem.writeBytes(descAddr, makeFilled(16, 0xcc))
	mem.put(t, structAddr, drmVersion{
		NameLen: v.NameLen,
		Name:    uint64(nameAddr),
		DateLen: v.DateLen,
		Date:    uint64(dateAddr),
		DescLen: v.DescLen,
		Desc:    uint64(descAddr),
	})
	if err := node.ioctl(fd, cmdVersion, mem, structAddr); err != nil {
		t.Fatalf("VERSION call 2: %v", err)
	}
	if got := string(mem.readBytes(nameAddr, 10)); got != "virtio_gpu" {
		t.Errorf("name = %q, want %q", got, "virtio_gpu")
	}
	if got := mem.readBytes(nameAddr+10, 1)[0]; got != 0xaa {
		t.Errorf("byte past name = %#x, want 0xaa (no NUL written)", got)
	}
	if got := string(mem.readBytes(dateAddr, 1)); got != "0" {
		t.Errorf("date = %q, want %q", got, "0")
	}
	if got := mem.readBytes(dateAddr+1, 1)[0]; got != 0xbb {
		t.Errorf("byte past date = %#x, want 0xbb (no NUL written)", got)
	}
	if got := string(mem.readBytes(descAddr, 10)); got != "virtio GPU" {
		t.Errorf("desc = %q, want %q", got, "virtio GPU")
	}
	if got := mem.readBytes(descAddr+10, 1)[0]; got != 0xcc {
		t.Errorf("byte past desc = %#x, want 0xcc (no NUL written)", got)
	}

	// Call 3: 3-byte buffers truncate the copy while reporting full lengths.
	mem.writeBytes(nameAddr, makeFilled(16, 0x55))
	mem.writeBytes(dateAddr, makeFilled(16, 0x66))
	mem.writeBytes(descAddr, makeFilled(16, 0x77))
	mem.put(t, structAddr, drmVersion{
		NameLen: 3,
		Name:    uint64(nameAddr),
		DateLen: 3,
		Date:    uint64(dateAddr),
		DescLen: 3,
		Desc:    uint64(descAddr),
	})
	if err := node.ioctl(fd, cmdVersion, mem, structAddr); err != nil {
		t.Fatalf("VERSION call 3: %v", err)
	}
	mem.get(t, structAddr, &v)
	if v.NameLen != 10 || v.DateLen != 1 || v.DescLen != 10 {
		t.Errorf("call 3 lengths = (%d, %d, %d), want (10, 1, 10)", v.NameLen, v.DateLen, v.DescLen)
	}
	if got := string(mem.readBytes(nameAddr, 3)); got != "vir" {
		t.Errorf("truncated name = %q, want %q", got, "vir")
	}
	if got := mem.readBytes(nameAddr+3, 1)[0]; got != 0x55 {
		t.Errorf("byte after truncated name = %#x, want 0x55", got)
	}
	if got := string(mem.readBytes(dateAddr, 1)); got != "0" {
		t.Errorf("date = %q, want %q", got, "0")
	}
	if got := mem.readBytes(dateAddr+1, 1)[0]; got != 0x66 {
		t.Errorf("byte after date = %#x, want 0x66", got)
	}
	if got := string(mem.readBytes(descAddr, 3)); got != "vir" {
		t.Errorf("truncated desc = %q, want %q", got, "vir")
	}
	if got := mem.readBytes(descAddr+3, 1)[0]; got != 0x77 {
		t.Errorf("byte after truncated desc = %#x, want 0x77", got)
	}
}

func TestDRMCoreGetCap(t *testing.T) {
	node := newTestNode(t, newFakeRenderer())
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)

	cases := []struct {
		name    string
		cap     uint64
		wantVal uint64
		wantErr error
	}{
		{"PRIME", drmCapPrime, 0, nil},
		{"TIMESTAMP_MONOTONIC", drmCapTimestampMonotonic, 1, nil},
		{"SYNCOBJ", drmCapSyncobj, 0, nil},
		{"SYNCOBJ_TIMELINE", drmCapSyncobjTimeline, 0, nil},
		{"DUMB_BUFFER", drmCapDumbBuffer, 0, linuxerr.EINVAL},
		{"unknown", 0xdead, 0, linuxerr.EINVAL},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mem.put(t, structAddr, drmGetCap{Capability: tc.cap, Value: 0xdeadbeef})
			err := node.ioctl(fd, cmdGetCap, mem, structAddr)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("GET_CAP(%#x): got %v, want nil", tc.cap, err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("GET_CAP(%#x): got %v, want %v", tc.cap, err, tc.wantErr)
			}
			var out drmGetCap
			mem.get(t, structAddr, &out)
			if out.Value != tc.wantVal {
				t.Errorf("GET_CAP(%#x) value = %#x, want %#x", tc.cap, out.Value, tc.wantVal)
			}
		})
	}
}

func makeFilled(n int, b byte) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}
