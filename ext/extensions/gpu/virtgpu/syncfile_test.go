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
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func TestSyncFileRefusesIoctlReadWrite(t *testing.T) {
	node := newTestNode(t, newFakeRenderer())
	sf, err := newSyncFile(node.ctx, node.vfs, &fence{id: 1})
	if err != nil {
		t.Fatalf("newSyncFile: %v", err)
	}
	defer sf.DecRef(node.ctx)

	if !sf.Epollable() {
		t.Errorf("Epollable() = false, want true")
	}

	mem := newGuestMem()
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: 0x1234}
	if _, err := sf.Ioctl(node.ctx, &mem.BytesIO, 0, args); !linuxerr.Equals(linuxerr.ENOTTY, err) {
		t.Errorf("sync_file Ioctl: got %v, want ENOTTY", err)
	}

	buf := make([]byte, 16)
	if _, err := sf.Read(node.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{}); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("sync_file Read: got %v, want EINVAL", err)
	}
	if _, err := sf.Write(node.ctx, usermem.BytesIOSequence(buf), vfs.WriteOptions{}); !linuxerr.Equals(linuxerr.EBADF, err) {
		t.Errorf("sync_file Write: got %v, want EBADF", err)
	}
}
