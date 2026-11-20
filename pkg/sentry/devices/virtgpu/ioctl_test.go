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
	"fmt"
	"strings"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
)

func TestIoctlSizeFollowsLinuxDRM(t *testing.T) {
	node := newTestNode(t, newFakeRenderer())
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)

	t.Run("smaller cmd size leaves upper guest bytes unchanged", func(t *testing.T) {
		mem.writeBytes(structAddr, makeFilled(16, 0xaa))
		var capBytes [8]byte
		binary.LittleEndian.PutUint64(capBytes[:], drmCapTimestampMonotonic)
		mem.writeBytes(structAddr, capBytes[:])

		cmd8 := linux.IOWR(drmIoctlBase, nrGetCap, 8)
		if err := node.ioctl(fd, cmd8, mem, structAddr); err != nil {
			t.Fatalf("GET_CAP(size=8): %v", err)
		}
		if got := mem.readBytes(structAddr+8, 8); !bytes.Equal(got, makeFilled(8, 0xaa)) {
			t.Errorf("bytes 8..15 = %x, want all 0xaa", got)
		}
	})

	t.Run("larger cmd size preserves trailing guest bytes", func(t *testing.T) {
		mem.put(t, structAddr, drmGetCap{Capability: drmCapTimestampMonotonic})
		trailing := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
		mem.writeBytes(structAddr+16, trailing)

		cmd24 := linux.IOWR(drmIoctlBase, nrGetCap, 24)
		if err := node.ioctl(fd, cmd24, mem, structAddr); err != nil {
			t.Fatalf("GET_CAP(size=24): %v", err)
		}
		var out drmGetCap
		mem.get(t, structAddr, &out)
		if out.Value != 1 {
			t.Errorf("GET_CAP(size=24) value = %d, want 1", out.Value)
		}
		if got := mem.readBytes(structAddr+16, 8); !bytes.Equal(got, trailing) {
			t.Errorf("bytes 16..23 = %x, want %x", got, trailing)
		}
	})

	t.Run("IOC_NONE performs no copy in or out", func(t *testing.T) {
		mem.put(t, structAddr, drmGetCap{Capability: drmCapTimestampMonotonic, Value: 0xbeef})
		before := mem.readBytes(structAddr, 16)

		cmdNone := linux.IOC(0, drmIoctlBase, nrGetCap, 16)
		if err := node.ioctl(fd, cmdNone, mem, structAddr); !linuxerr.Equals(linuxerr.EINVAL, err) {
			t.Fatalf("GET_CAP(_IOC_NONE): got %v, want EINVAL", err)
		}
		if after := mem.readBytes(structAddr, 16); !bytes.Equal(after, before) {
			t.Errorf("guest memory changed on _IOC_NONE: got %x, want %x", after, before)
		}
	})

	t.Run("bad argument address returns EFAULT", func(t *testing.T) {
		if err := node.ioctl(fd, cmdVersion, mem, badGuestAddr); !linuxerr.Equals(linuxerr.EFAULT, err) {
			t.Errorf("VERSION(bad addr): got %v, want EFAULT", err)
		}
	})
}

func TestRefusedIoctls(t *testing.T) {
	node := newTestNode(t, newFakeRenderer())
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()

	for nr, r := range refusedIoctls {
		cmd := linux.IOWR(drmIoctlBase, nr, 0)
		err := node.ioctl(fd, cmd, mem, badGuestAddr)
		if !errors.Is(err, r.err) {
			t.Errorf("refused %s (nr %#x): got %v, want %v", r.name, nr, err, r.err)
		}
	}

	// Unknown DRM request numbers return EINVAL.
	for _, nr := range []uint32{0x3e, 0xd3} {
		cmd := linux.IOWR(drmIoctlBase, nr, 0)
		if err := node.ioctl(fd, cmd, mem, badGuestAddr); !linuxerr.Equals(linuxerr.EINVAL, err) {
			t.Errorf("unknown DRM nr %#x: got %v, want EINVAL", nr, err)
		}
	}

	// Non-DRM ioctl type (TCGETS = 0x5401) returns ENOTTY.
	if err := node.ioctl(fd, linux.TCGETS, mem, badGuestAddr); !linuxerr.Equals(linuxerr.ENOTTY, err) {
		t.Errorf("TCGETS: got %v, want ENOTTY", err)
	}
}

func TestBuildIoctlTablePanicsOnOverlap(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("buildIoctlTableFrom did not panic on duplicate request number")
		}
	}()
	buildIoctlTableFrom(
		map[uint32]ioctlEntry{nrVersion: {name: "DRM_IOCTL_VERSION", cmd: cmdVersion, fn: (*renderFD).version}},
		map[uint32]refusal{nrVersion: {name: "DRM_IOCTL_VERSION", err: linuxerr.EINVAL}},
	)
}

type captureDebugCtx struct {
	context.Context
	mu    sync.Mutex
	lines []string
}

func (c *captureDebugCtx) Debugf(format string, v ...any) {
	c.mu.Lock()
	c.lines = append(c.lines, fmt.Sprintf(format, v...))
	c.mu.Unlock()
}

func (c *captureDebugCtx) takeLines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.lines
	c.lines = nil
	return out
}

func TestModeGatedIoctls(t *testing.T) {
	t.Run("venus refuses virgl ioctls with EINVAL and logs once each", func(t *testing.T) {
		node := newTestNode(t, newFakeRenderer())
		fd := node.open(t)
		defer fd.DecRef(node.ctx)
		dctx := &captureDebugCtx{Context: node.ctx}
		mem := newGuestMem()

		gated := []struct {
			name string
			cmd  uint32
		}{
			{"DRM_IOCTL_VIRTGPU_RESOURCE_CREATE", cmdVirtgpuResourceCreate},
			{"DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST", cmdVirtgpuTransferFromHost},
			{"DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST", cmdVirtgpuTransferToHost},
			{"DRM_IOCTL_VIRTGPU_WAIT", cmdVirtgpuWait},
		}
		for _, tc := range gated {
			for attempt := range 2 {
				err := node.ioctlWithCtx(dctx, fd, tc.cmd, mem, badGuestAddr)
				if !linuxerr.Equals(linuxerr.EINVAL, err) {
					t.Errorf("%s attempt %d: got %v, want EINVAL", tc.name, attempt+1, err)
				}
			}
			lines := dctx.takeLines()
			if len(lines) != 1 || !strings.Contains(lines[0], "refused ioctl "+tc.name) {
				t.Errorf("%s debug lines = %q, want 1 line naming %s", tc.name, lines, tc.name)
			}
		}
	})

	t.Run("virgl refuses RESOURCE_CREATE_BLOB with EINVAL and logs once", func(t *testing.T) {
		node := newTestNode(t, newFakeVirglRenderer())
		fd := node.open(t)
		defer fd.DecRef(node.ctx)
		dctx := &captureDebugCtx{Context: node.ctx}
		mem := newGuestMem()

		for attempt := range 2 {
			err := node.ioctlWithCtx(dctx, fd, cmdVirtgpuResourceCreateBlob, mem, badGuestAddr)
			if !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Errorf("RESOURCE_CREATE_BLOB attempt %d: got %v, want EINVAL", attempt+1, err)
			}
		}
		lines := dctx.takeLines()
		const wantName = "DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB"
		if len(lines) != 1 || !strings.Contains(lines[0], "refused ioctl "+wantName) {
			t.Errorf("RESOURCE_CREATE_BLOB debug lines = %q, want 1 line naming %s", lines, wantName)
		}
	})
}
