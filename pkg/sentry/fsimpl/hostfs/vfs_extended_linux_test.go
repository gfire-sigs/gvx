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

//go:build linux

package hostfs

import (
	"testing"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
)

// hostVolumeOf reads the volume of dir the way the host backend does.
func hostVolumeOf(t *testing.T, dir string) hostVolume {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	unit := uint64(st.Frsize)
	if unit == 0 {
		unit = uint64(st.Bsize)
	}
	return hostVolume{blockSize: unit, blocks: st.Blocks, free: st.Bfree, avail: st.Bavail, files: st.Files, filesFree: st.Ffree}
}

// TestTmpfileWithExclHoldsNoHostNameOnLinux checks the native O_TMPFILE
// path. The volume of the test may refuse O_TMPFILE. The fallback removes
// the name at once, so the host directory is empty in both cases.
func TestTmpfileWithExclHoldsNoHostNameOnLinux(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpenTmp(".", linux.O_RDWR|linux.O_EXCL)
	defer fd.DecRef(e.ctx)
	e.pwriteAt(fd, 0, "anonymous")
	if got := e.hostEntries("."); len(got) != 0 {
		t.Fatalf("host entries while an O_EXCL temporary file is open = %v, want none", got)
	}
	// The host kernel agrees that no name reaches the file.
	h := fd.Impl().(*regularFD).h
	info, err := h.fstat(e.ws.host)
	if err != nil {
		t.Fatal(err)
	}
	if info.nlink != 0 {
		t.Fatalf("host link count of an O_EXCL temporary file = %d, want 0", info.nlink)
	}
	if got := e.pread(fd, 0, 9); string(got) != "anonymous" {
		t.Fatalf("read back = %q", got)
	}
}

// TestTmpfileWithoutExclUsesAHiddenHostNameOnLinux shows the other path: a
// file that the guest may link keeps a hidden host name, because the seccomp
// rule of the host filesystem refuses linkat with AT_EMPTY_PATH.
func TestTmpfileWithoutExclUsesAHiddenHostNameOnLinux(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpenTmp(".", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	got := e.hostEntries(".")
	if len(got) != 1 || !isEphemeralName(got[0]) {
		t.Fatalf("host entries = %v, want one hidden internal name", got)
	}
}
