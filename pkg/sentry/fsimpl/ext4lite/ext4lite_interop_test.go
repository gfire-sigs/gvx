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

package ext4lite

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// interopFiles lists the regular files of the interop image. The sizes cover
// the inline form at its edges, and a file that needs extent leaf blocks.
func interopFiles() map[string][]byte {
	files := map[string][]byte{
		"inline-0":                    nil,
		"inline-60":                   pattern(1, 60),
		"inline-156":                  pattern(2, 156),
		"dir1/dir2/dir3/deep.txt":     []byte("deep file\n"),
		"dir1/dir2/readme":            pattern(3, 5000),
		"extents-10m":                 nil,
		"spacer":                      nil,
		"dir1/medium-3-extents":       pattern(4, 3*blockSize),
		"dir1/xattr-file":             []byte("has attributes\n"),
		"linked-original":             []byte("one inode, two names\n"),
		"dir1/dir2/dir3/dir4/end.bin": pattern(5, 70000),
	}
	return files
}

// buildInteropImage writes the interop tree through the VFS layer and ends
// with a clean unmount.
func buildInteropImage(t *testing.T) string {
	t.Helper()
	e := newEnv(t)
	for _, d := range []string{"dir1", "dir1/dir2", "dir1/dir2/dir3", "dir1/dir2/dir3/dir4", "emptydir"} {
		e.mustMkdir(d)
	}
	files := interopFiles()
	for name, data := range files {
		if name == "extents-10m" || name == "spacer" {
			continue
		}
		e.writeFile(name, data)
	}
	// Two files that grow in turn get interleaved blocks, so the first file
	// ends with many extents.
	big, spacer := e.mustOpen("extents-10m", linux.O_CREAT|linux.O_WRONLY), e.mustOpen("spacer", linux.O_CREAT|linux.O_WRONLY)
	const piece, total = 64 << 10, 10 << 20
	for off := 0; off < total; off += piece {
		e.pwrite(big, pattern(byte(off/piece), piece), int64(off))
		e.pwrite(spacer, pattern(0xAA, 4096), int64(off/piece)*4096)
	}
	big.DecRef(e.ctx)
	spacer.DecRef(e.ctx)

	if err := e.symlink("inline-60", "link-short"); err != nil {
		t.Fatal(err)
	}
	if err := e.symlink(strings.Repeat("../", 40)+"inline-156", "link-long"); err != nil {
		t.Fatal(err)
	}
	if err := e.link("linked-original", "linked-second"); err != nil {
		t.Fatal(err)
	}
	if err := e.link("linked-original", "dir1/linked-third"); err != nil {
		t.Fatal(err)
	}
	for path, attrs := range map[string]map[string]string{
		"dir1/xattr-file": {"user.alpha": "1", "user.beta": strings.Repeat("b", 900), "trusted.note": "t"},
		"dir1":            {"user.dir": "directory"},
	} {
		for name, value := range attrs {
			if err := e.vfsObj.SetXattrAt(e.ctx, e.creds, e.fpop(path), &vfs.SetXattrOptions{Name: name, Value: value}); err != nil {
				t.Fatalf("setxattr %s %s: %v", path, name, err)
			}
		}
	}
	if err := e.vfsObj.MknodAt(e.ctx, e.creds, e.pop("fifo"), &vfs.MknodOptions{Mode: linux.S_IFIFO | 0o640}); err != nil {
		t.Fatal(err)
	}
	if err := e.setStat("dir1/dir2/readme", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	path := e.path
	e.unmount()
	return path
}

// TestInteropE2fsck builds the image and expects e2fsck to accept it. The
// extent file must have grown past the root of the tree and the volume must
// open again with the same content.
func TestInteropE2fsck(t *testing.T) {
	path := buildInteropImage(t)
	runE2fsck(t, path)
}

// TestInteropContentSurvivesRemount reads the image back through the VFS layer.
func TestInteropContentSurvivesRemount(t *testing.T) {
	path := buildInteropImage(t)
	e := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})
	for name, data := range interopFiles() {
		switch name {
		case "extents-10m", "spacer":
			continue
		}
		wantBytes(t, name, e.readFile(name), data)
	}
	got := e.readFile("extents-10m")
	if len(got) != 10<<20 {
		t.Fatalf("extents-10m has %d bytes", len(got))
	}
	for off := 0; off < len(got); off += 64 << 10 {
		wantBytes(t, fmt.Sprintf("extents-10m at %d", off), got[off:off+64<<10], pattern(byte(off/(64<<10)), 64<<10))
	}
	if st := e.mustStat("linked-second"); st.Nlink != 3 {
		t.Errorf("link count = %d, want 3", st.Nlink)
	}
	if st := e.mustStat("dir1/dir2/readme"); st.Mode&0o777 != 0o600 {
		t.Errorf("mode = %o, want 600", st.Mode&0o777)
	}
	e.unmount()

	// The leaf blocks exist only when the file has more than four extents.
	v := reopenVolume(t, path)
	n := lookupNode(t, v, mustRoot(t, v), "extents-10m")
	n.mu.RLock()
	exts, leaves := len(n.exts), len(n.leaves)
	n.mu.RUnlock()
	if exts < 5 || leaves == 0 {
		t.Errorf("extents-10m has %d extents in %d leaves, want a depth-1 tree", exts, leaves)
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
}

// TestInteropKernelMount mounts the image through the Linux kernel loop driver
// and compares the files that it lists. It runs only on Linux with enough
// privilege. EXT4LITE_REQUIRE_LOOPMOUNT makes a missing prerequisite fail.
func TestInteropKernelMount(t *testing.T) {
	skip := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("EXT4LITE_REQUIRE_LOOPMOUNT") != "" {
			t.Fatalf(format, args...)
		}
		t.Skipf(format, args...)
	}
	if runtime.GOOS != "linux" {
		skip("the loop mount needs Linux")
	}
	var priv []string
	if os.Geteuid() != 0 {
		if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
			skip("no root and no passwordless sudo: %v", err)
		}
		priv = []string{"sudo", "-n"}
	}
	run := func(args ...string) ([]byte, error) {
		full := append(append([]string{}, priv...), args...)
		return exec.Command(full[0], full[1:]...).CombinedOutput()
	}
	// The files belong to root with the modes that the guest chose, so the
	// test reads them with the same privilege as the mount.
	readPriv := func(p string) ([]byte, error) {
		full := append(append([]string{}, priv...), "cat", p)
		return exec.Command(full[0], full[1:]...).Output()
	}
	path := buildInteropImage(t)
	mnt := t.TempDir()
	if out, err := run("mount", "-o", "loop,ro", "-t", "ext4", path, mnt); err != nil {
		skip("mount -o loop failed: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = run("umount", mnt) })

	for name, data := range interopFiles() {
		switch name {
		case "extents-10m", "spacer":
			continue
		}
		got, err := readPriv(filepath.Join(mnt, name))
		if err != nil {
			t.Errorf("kernel read of %s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, data) {
			t.Errorf("kernel read of %s: %d bytes differ from the %d bytes written", name, len(got), len(data))
		}
	}
	big, err := readPriv(filepath.Join(mnt, "extents-10m"))
	if err != nil || len(big) != 10<<20 {
		t.Fatalf("kernel read of extents-10m: %d bytes, %v", len(big), err)
	}
	for off := 0; off < len(big); off += 64 << 10 {
		if !bytes.Equal(big[off:off+64<<10], pattern(byte(off/(64<<10)), 64<<10)) {
			t.Fatalf("kernel read of extents-10m differs at %d", off)
		}
	}
	if target, err := os.Readlink(filepath.Join(mnt, "link-short")); err != nil || target != "inline-60" {
		t.Errorf("kernel readlink of link-short = %q, %v", target, err)
	}
	if target, err := os.Readlink(filepath.Join(mnt, "link-long")); err != nil || target != strings.Repeat("../", 40)+"inline-156" {
		t.Errorf("kernel readlink of link-long = %q, %v", target, err)
	}
	a, errA := os.Stat(filepath.Join(mnt, "linked-original"))
	b, errB := os.Stat(filepath.Join(mnt, "dir1", "linked-third"))
	if errA != nil || errB != nil || !os.SameFile(a, b) {
		t.Errorf("hard links are not one file: %v, %v", errA, errB)
	}
	if out, err := exec.Command("getfattr", "-n", "user.alpha", "--only-values", filepath.Join(mnt, "dir1", "xattr-file")).Output(); err == nil && string(out) != "1" {
		t.Errorf("kernel xattr user.alpha = %q, want 1", out)
	}
}
