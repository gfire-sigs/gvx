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

//go:build !windows

package hostfs

import (
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// TestStatFSMatchesTheHostVolume compares the numbers of the guest with the
// numbers that the host reports for the workspace directory.
func TestStatFSMatchesTheHostVolume(t *testing.T) {
	e := newEnv(t)
	want := hostVolumeOf(t, e.dir)
	st, err := e.vfsObj.StatFSAt(e.ctx, e.creds, e.fpop("."))
	if err != nil {
		t.Fatal(err)
	}
	if uint64(st.BlockSize) != want.blockSize || st.Blocks != want.blocks {
		t.Fatalf("guest volume = (block size %d, blocks %d), host volume = (%d, %d)", st.BlockSize, st.Blocks, want.blockSize, want.blocks)
	}
}

// TestHostSymlinksStayHiddenWhileGuestSymlinksStayVirtual puts native links on
// the host next to guest links. Native links that leave the workspace stay
// hidden from the guest, and guest links never appear on the host.
func TestHostSymlinksStayHiddenWhileGuestSymlinksStayVirtual(t *testing.T) {
	e := newEnv(t)
	outside := t.TempDir()
	if err := os.WriteFile(outside+"/secret", []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"hostabs": outside,
		"hostup":  "../..",
	} {
		if err := os.Symlink(target, e.host(name)); err != nil {
			t.Skipf("host cannot create symbolic links: %v", err)
		}
	}
	if err := e.symlink("guestabs", outside); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hostabs", "hostup"} {
		_, err := e.lstat(name)
		wantErrno(t, "lstat of the host link "+name, err, linuxerr.EACCES)
	}
	if got := e.readdir("."); len(got) != 1 || got[0] != "guestabs" {
		t.Fatalf("listing = %v, want only the guest link", got)
	}
	// The guest link names the same host directory, and the guest never
	// reaches it: the string resolves in the guest namespace.
	_, err := e.open("guestabs/secret", linux.O_RDONLY, 0)
	wantErrno(t, "open through a guest link to a host path", err, linuxerr.ENOENT)
	if _, err := os.Lstat(e.host("guestabs")); !os.IsNotExist(err) {
		t.Fatalf("the guest link reached the host: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(e.host("hostabs"), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK {
		t.Fatalf("the host link changed: %v", err)
	}
}
