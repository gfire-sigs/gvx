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

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

func TestRenderNodeInDevtmpfs(t *testing.T) {
	node := newTestNode(t, newFakeRenderer())

	for _, p := range []string{"/dri/renderD128", "/char/226:128"} {
		pop := node.pop(p)
		pop.FollowFinalSymlink = true
		st, err := node.vfs.StatAt(node.ctx, node.creds, pop, &vfs.StatOptions{
			Mask: linux.STATX_TYPE | linux.STATX_MODE,
		})
		if err != nil {
			t.Fatalf("StatAt(%s): %v", p, err)
		}
		if got := linux.FileMode(st.Mode).FileType(); got != linux.S_IFCHR {
			t.Errorf("%s type = %#o, want S_IFCHR", p, got)
		}
		if got := linux.FileMode(st.Mode).Permissions(); got != 0666 {
			t.Errorf("%s mode = %#o, want 0666", p, got)
		}
		if st.RdevMajor != DRMMajor || st.RdevMinor != RenderMinor {
			t.Errorf("%s rdev = %d:%d, want %d:%d", p, st.RdevMajor, st.RdevMinor, DRMMajor, RenderMinor)
		}
	}
}

func TestRegisterRefusesRendererWithoutVenus(t *testing.T) {
	fake := &fakeRenderer{
		capsets:  map[capsetKey][]byte{},
		contexts: make(map[uint32]createCall),
	}
	v := &vfs.VirtualFilesystem{}
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}

	if _, err := Register(v, fake, Limits{}); !errors.Is(err, ErrNoVenusCapset) {
		t.Fatalf("Register without venus capset: got %v, want ErrNoVenusCapset", err)
	}
	if fake.hasSink() {
		t.Errorf("SetEventSink was called despite Register failing")
	}
}

func TestRegisterAfterRendererLoss(t *testing.T) {
	fake := newFakeRenderer()
	fake.lostBeforeSink = true
	fake.lostErr = errors.New("renderer crashed before sink install")

	node := newTestNode(t, fake)
	fd := node.open(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	putContextInit(t, mem, 0x1000, 0x2000, mesaVenusParams())
	if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, 0x1000); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Fatalf("CONTEXT_INIT after pre-sink loss: got %v, want EIO", err)
	}
	if got := len(fake.createdCalls()); got != 0 {
		t.Errorf("CreateContext calls after renderer loss = %d, want 0", got)
	}
}

func TestReadAndPoll(t *testing.T) {
	node := newTestNode(t, newFakeRenderer())
	fd := node.openFlags(t, linux.O_RDWR|linux.O_NONBLOCK)
	defer fd.DecRef(node.ctx)

	buf := make([]byte, 64)
	if _, err := fd.Read(node.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{}); !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		t.Errorf("Read on O_NONBLOCK render node: got %v, want ErrWouldBlock", err)
	}
	if got := fd.Readiness(waiter.ReadableEvents | waiter.WritableEvents); got != 0 {
		t.Errorf("Readiness = %#x, want 0", got)
	}
	if !fd.Epollable() {
		t.Errorf("Epollable() = false, want true")
	}
}
