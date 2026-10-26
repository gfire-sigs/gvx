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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// The tests below check the journal against the tools of Linux. They need
// e2fsprogs or a loop mount, so they skip when the tool is missing. The CI job
// on Linux sets EXT4LITE_REQUIRE_E2FSCK and EXT4LITE_REQUIRE_LOOPMOUNT, and a
// missing tool then fails the test.

// auCrashImageFile writes the crash image of a rich workload to a host file and
// returns the path and the model of the content. The log holds every
// transaction, and the image asks for recovery.
func auCrashImageFile(t *testing.T) (string, *auModel) {
	t.Helper()
	d := newAuDrv(t)
	auRichWorkload(d)
	d.syncAll()
	crash := d.f.snapshot()
	if j, _ := auReadJournal(crash); j == nil || j.start == 0 {
		t.Fatal("the crash image has no log to replay")
	}
	path := filepath.Join(t.TempDir(), "crash.ext4")
	if err := os.WriteFile(path, crash.bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, d.m
}

// auExitCode returns the exit code of a finished command, or -1.
func auExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}

func auRequireTool(t *testing.T, name, requireVar string) string {
	t.Helper()
	bin, err := exec.LookPath(name)
	if err != nil {
		if os.Getenv(requireVar) != "" {
			t.Fatalf("%s is not installed, and %s is set", name, requireVar)
		}
		t.Skipf("%s is not installed", name)
	}
	return bin
}

// TestInteropE2fsckReplaysOurJournal gives e2fsck the image of a crashed
// session. e2fsck must replay the log, report a clean file system on the next
// check, and leave every file of the workload in place.
func TestInteropE2fsckReplaysOurJournal(t *testing.T) {
	bin := auRequireTool(t, "e2fsck", "EXT4LITE_REQUIRE_E2FSCK")
	path, model := auCrashImageFile(t)
	out, err := exec.Command(bin, "-fy", path).CombinedOutput()
	if code := auExitCode(err); code != 0 && code != 1 {
		t.Fatalf("e2fsck -fy exits with %d:\n%s", code, bytes.TrimSpace(out))
	}
	if out, err := exec.Command(bin, "-fn", path).CombinedOutput(); err != nil {
		t.Fatalf("e2fsck -fn after the replay: %v\n%s", err, bytes.TrimSpace(out))
	}
	e := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})
	for _, msg := range auCompareLive(e, model) {
		t.Errorf("after the replay by e2fsck: %s", msg)
	}
}

// TestInteropKernelReplaysOurJournal mounts the crash image read-write through
// the loop driver. The kernel replays the log on mount. After the unmount, the
// engine must read every file of the workload.
func TestInteropKernelReplaysOurJournal(t *testing.T) {
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
	path, model := auCrashImageFile(t)
	mnt := t.TempDir()
	if out, err := run("mount", "-o", "loop", "-t", "ext4", path, mnt); err != nil {
		skip("mount -o loop failed: %v\n%s", err, out)
	}
	if out, err := run("umount", mnt); err != nil {
		t.Fatalf("umount: %v\n%s", err, out)
	}
	if len(priv) > 0 {
		// The kernel mount can change the owner of the image file with sudo.
		if out, err := run("chown", strconv.Itoa(os.Getuid()), path); err != nil {
			t.Fatalf("chown of the image: %v\n%s", err, out)
		}
	}
	e := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})
	for _, msg := range auCompareLive(e, model) {
		t.Errorf("after the replay by the kernel: %s", msg)
	}
}

// TestInteropEngineReplaysADebugfsTransaction lets debugfs write a transaction
// in the format of the kernel: one data block of a file, through the journal of
// the image. The engine must replay it at mount, so the file shows the new
// bytes. debugfs journal commands need e2fsprogs 1.43 or newer, and the test
// skips when they fail.
func TestInteropEngineReplaysADebugfsTransaction(t *testing.T) {
	bin := auRequireTool(t, "debugfs", "EXT4LITE_REQUIRE_E2FSCK")
	d := newAuDrv(t)
	d.create("/target", 3*blockSize)
	d.e.unmount()
	img := d.f.snapshot()
	res := auFsck(img, true)
	var block uint64
	for blk, owner := range res.Blocks {
		if owner == res.Tree["/target"].ino && (block == 0 || blk < block) {
			block = blk
		}
	}
	if block == 0 {
		t.Fatal("no block of /target")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vol.ext4")
	if err := os.WriteFile(path, img.bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := auFill(4242, 0, blockSize)
	data := filepath.Join(dir, "block.bin")
	if err := os.WriteFile(data, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	cmds := filepath.Join(dir, "cmds")
	script := "jo\njw -b " + itoa(block) + " " + data + "\njc\n"
	if err := os.WriteFile(cmds, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "-w", "-f", cmds, path).CombinedOutput(); err != nil {
		t.Skipf("debugfs cannot write a journal transaction: %v\n%s", err, bytes.TrimSpace(out))
	}
	e := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})
	got := e.readFile("/target")
	if len(got) < blockSize || !bytes.Equal(got[:blockSize], payload) {
		t.Errorf("the first block of /target does not show the debugfs transaction")
	}
}

func itoa(n uint64) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		if n /= 10; n == 0 {
			return string(b[i:])
		}
	}
}
