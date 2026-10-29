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

//go:build darwin

package hostfs

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// hostVolumeOf reads the volume of dir the way the host backend does.
func hostVolumeOf(t *testing.T, dir string) hostVolume {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	return hostVolume{blockSize: uint64(st.Bsize), blocks: st.Blocks, free: st.Bfree, avail: st.Bavail, files: st.Files, filesFree: st.Ffree}
}

func TestDarwinNativeCallsAreInUse(t *testing.T) {
	e := newEnv(t)
	caps := e.ws.Caps()
	if !caps.NativeRenameSwap || !caps.NativeFallocate {
		t.Fatalf("caps = %+v, want native rename swap and fallocate on APFS", caps)
	}
	e.writeFile("a", []byte("A"))
	e.writeFile("b", []byte("B"))
	// The host rename swap runs in one call: no swap file ever exists.
	if err := e.renameFlags("a", "b", linux.RENAME_EXCHANGE); err != nil {
		t.Fatal(err)
	}
	if got := e.hostRead("a"); got != "B" {
		t.Fatalf("host a = %q, want B", got)
	}
}

// TestDarwinAllocateReservesSpace checks that mode 0 reserves blocks on APFS
// with F_PREALLOCATE, and that KEEP_SIZE keeps the size.
func TestDarwinAllocateReservesSpace(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", nil)
	fd := e.mustOpen("f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	const reserve = 4 << 20
	if err := allocate(e, fd, keepSize, 0, reserve); err != nil {
		t.Fatalf("allocate with KEEP_SIZE: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Stat(e.host("f"), &st); err != nil {
		t.Fatal(err)
	}
	if st.Size != 0 {
		t.Fatalf("size after KEEP_SIZE = %d, want 0", st.Size)
	}
	if st.Blocks*512 < reserve {
		t.Skipf("the volume of the test did not reserve blocks (%d bytes): F_PREALLOCATE is advisory on this file system", st.Blocks*512)
	}
	if err := allocate(e, fd, 0, 0, reserve); err != nil {
		t.Fatalf("allocate mode 0: %v", err)
	}
	if err := unix.Stat(e.host("f"), &st); err != nil || st.Size != reserve {
		t.Fatalf("size after mode 0 = (%d, %v), want %d", st.Size, err, reserve)
	}
}

// The Seatbelt profile allows file writes only below the workspace. The next
// test re-executes the test binary as a locked child and runs the extended
// operations there, because the lockdown cannot be undone.

const extendedLockedChildEnv = "GVX_HOSTFS_EXT_LOCKED_CHILD"

func TestExtendedOperationsWorkAfterTheHostLockdown(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestExtendedOperationsLockedChild$", "-test.v")
	cmd.Env = append(os.Environ(), extendedLockedChildEnv+"="+dir, "GORACE=atexit_sleep_ms=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("locked child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("locked child did not pass:\n%s", out)
	}
}

// TestExtendedOperationsLockedChild is the body of the locked child. It does
// nothing in the normal test run.
func TestExtendedOperationsLockedChild(t *testing.T) {
	dir := os.Getenv(extendedLockedChildEnv)
	if dir == "" {
		t.Skip("runs only as the locked child of TestExtendedOperationsWorkAfterTheHostLockdown")
	}
	ws, err := openWorkspace(dir, false, workspaceOptions{coalesce: defaultCoalesceWindow})
	if err != nil {
		t.Fatal(err)
	}
	e := mountEnv(t, ws, dir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		_ = ws.Close()
	})
	e.mustMkdir("d")
	e.mustMkdir("e")
	e.writeFile("d/a", []byte("A"))
	e.writeFile("d/b", []byte("B"))
	e.writeFile("e/c", []byte("C"))
	e.writeFile("big", bytes.Repeat([]byte{7}, 256<<10))
	e.readdir("d")

	if _, err := hostlockdown.Apply(hostlockdown.Options{Mounts: []hostlockdown.HostMount{{Path: dir}}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !hostlockdown.IsLockedDown() {
		t.Fatal("the process is not locked down after Apply")
	}
	// Proof that the profile is live: a new open outside the workspace fails.
	if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "outside-after-lockdown"), []byte("x"), 0o600); err == nil {
		t.Fatal("the lockdown allowed a file create outside the workspace")
	}

	// RENAME_SWAP through renameatx_np, for files and for directories.
	if err := e.renameFlags("d/a", "d/b", linux.RENAME_EXCHANGE); err != nil {
		t.Fatalf("file exchange after the lockdown: %v", err)
	}
	if got := e.readFile("d/a"); string(got) != "B" {
		t.Fatalf("d/a = %q, want B", got)
	}
	if err := e.renameFlags("d", "e", linux.RENAME_EXCHANGE); err != nil {
		t.Fatalf("directory exchange after the lockdown: %v", err)
	}
	if got := e.readFile("e/a"); string(got) != "B" {
		t.Fatalf("e/a = %q, want B", got)
	}
	// The whiteout and the plain rename.
	if err := e.renameFlags("e/a", "e/moved", linux.RENAME_WHITEOUT); err != nil {
		t.Fatalf("whiteout rename after the lockdown: %v", err)
	}
	// F_PREALLOCATE, ftruncate, and F_PUNCHHOLE.
	fd := e.mustOpen("big", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if err := allocate(e, fd, 0, 256<<10, 1<<20); err != nil {
		t.Fatalf("allocate after the lockdown: %v", err)
	}
	if err := allocate(e, fd, keepSize, 0, 4<<20); err != nil {
		t.Fatalf("allocate with KEEP_SIZE after the lockdown: %v", err)
	}
	page := uint64(os.Getpagesize())
	if err := allocate(e, fd, punch, page, 2*page); err != nil {
		t.Fatalf("punch after the lockdown: %v", err)
	}
	if got := e.pread(fd, int64(page), 8); !bytes.Equal(got, make([]byte, 8)) {
		t.Fatalf("punched range = %v, want zeros", got)
	}
	// fstatfs.
	if st, err := e.vfsObj.StatFSAt(e.ctx, e.creds, e.fpop("big")); err != nil || st.Blocks == 0 {
		t.Fatalf("StatFSAt after the lockdown = (%+v, %v)", st, err)
	}
	// A temporary file: create, write, link.
	tmp := e.mustOpenTmp("e", linux.O_RDWR)
	defer tmp.DecRef(e.ctx)
	e.pwriteAt(tmp, 0, "tmp")
	if err := e.linkFD(tmp, "e/linked"); err != nil {
		t.Fatalf("link of a temporary file after the lockdown: %v", err)
	}
	// fsync of the file and of a directory.
	if err := tmp.Sync(e.ctx); err != nil {
		t.Fatalf("fsync after the lockdown: %v", err)
	}
	dfd := e.mustOpen("e", linux.O_RDONLY|linux.O_DIRECTORY)
	defer dfd.DecRef(e.ctx)
	if err := dfd.Sync(e.ctx); err != nil {
		t.Fatalf("directory fsync after the lockdown: %v", err)
	}
	// Unlink of an open file.
	if err := e.unlink("e/linked"); err != nil {
		t.Fatal(err)
	}
}
