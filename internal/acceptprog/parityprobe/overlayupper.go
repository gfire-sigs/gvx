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

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

// The overlay upper checks run an overlay mount whose upper layer lives on the
// directory that the caller names. That directory is on a volume, on a bind
// mount, or on tmpfs. The lower layer is a private tmpfs.
const (
	overlayLowerDir  = "/ovl/lower"
	overlayMergedDir = "/ovl/merged"
	opaqueXattr      = "trusted.overlay.opaque"
)

// lowerFiles is the content of the lower layer before any overlay write.
var lowerFiles = map[string]string{
	"del":       "lower del\n",
	"recreate":  "lower recreate\n",
	"gone":      "lower gone\n",
	"src2":      "lower src2\n",
	"cu":        "lower cu\n",
	"hl":        "lower hl\n",
	"keep":      "lower keep\n",
	"dir/a":     "lower dir/a\n",
	"dir/b":     "lower dir/b\n",
	"dir/sub/c": "lower dir/sub/c\n",
	"stay/x":    "lower stay/x\n",
	// The next names need an escape on a Windows host or on a host that
	// folds case. The overlay must keep them apart in whiteouts too.
	"Mixed": "lower Mixed\n",
	"mixed": "lower mixed\n",
	"con":   "lower con\n",
	"q?x":   "lower q?x\n",
}

// overlayRun is a named step of an overlay mode.
type overlayRun struct {
	name string
	fn   func() error
}

// runOverlayRuns runs each step, prints PASS or FAIL for it, and ends the
// probe with a failure status when a step fails.
func runOverlayRuns(steps []overlayRun) bool {
	ok := true
	for _, s := range steps {
		if err := s.fn(); err != nil {
			fmt.Printf("FAIL %s: %v\n", s.name, err)
			ok = false
			continue
		}
		fmt.Printf("PASS %s\n", s.name)
	}
	return ok
}

// overlayUpperPaths names the layers that one upper directory holds.
type overlayUpperPaths struct {
	upper, work string
	rawWhiteout string
	rawOpaque   string
}

func upperPaths(dir string) overlayUpperPaths {
	return overlayUpperPaths{
		upper:       filepath.Join(dir, "up"),
		work:        filepath.Join(dir, "wk"),
		rawWhiteout: filepath.Join(dir, "raw-whiteout"),
		rawOpaque:   filepath.Join(dir, "raw-opaque"),
	}
}

// runOverlayUpper dispatches the overlay-upper modes:
//
//	overlay-upper DIR           write the state, then verify it after a new mount
//	overlay-write DIR [hold]    write the state; with hold, sync and sleep
//	overlay-verify DIR          verify the state that an earlier run wrote
func runOverlayUpper(mode, dir string, hold bool) bool {
	p := upperPaths(dir)
	switch mode {
	case "overlay-upper":
		return runOverlayRuns(append(overlayWriteSteps(p), overlayVerifySteps(p)...))
	case "overlay-write":
		if !runOverlayRuns(overlayWriteSteps(p)) {
			return false
		}
		if hold {
			if err := syncUpper(dir); err != nil {
				fmt.Println("FAIL overlay-sync:", err)
				return false
			}
			fmt.Println("SYNCED")
			time.Sleep(time.Minute)
		}
		return true
	case "overlay-verify":
		return runOverlayRuns(overlayVerifySteps(p))
	}
	fmt.Fprintln(os.Stderr, "unknown overlay mode", mode)
	return false
}

func overlayWriteSteps(p overlayUpperPaths) []overlayRun {
	return []overlayRun{
		{"raw-whiteout-mknod", func() error { return rawWhiteoutCreate(p.rawWhiteout) }},
		{"raw-opaque-xattr", func() error { return rawOpaqueCreate(p.rawOpaque) }},
		{"overlay-refuses-proc-upper", refuseProcUpper},
		{"overlay-mount", func() error { return mountOverlay(p) }},
		{"overlay-initial-view", checkInitialView},
		{"overlay-delete-lower-file", func() error { return overlayDelete(p) }},
		{"overlay-recreate-deleted", overlayRecreate},
		{"overlay-rename-over-deleted", overlayRenameOverDeleted},
		{"overlay-rename-lower-file", overlayRenameLower},
		{"overlay-opaque-directory", overlayOpaqueDir},
		{"overlay-copy-up-write", overlayCopyUp},
		{"overlay-hardlink-copy-up", overlayHardlink},
		{"overlay-awkward-names", overlayAwkwardNames},
		{"overlay-final-view", func() error { return checkFinalView(p) }},
		{"overlay-umount", unmountOverlay},
		{"overlay-exec-from-layers", func() error { return overlayExecFromLayers(p) }},
		{"overlay-nonroot-owns-new-files", func() error { return overlayNonRootCreates(p) }},
	}
}

func overlayVerifySteps(p overlayUpperPaths) []overlayRun {
	return []overlayRun{
		{"raw-whiteout-reread", func() error { return statWhiteout(p.rawWhiteout) }},
		{"raw-opaque-reread", func() error { return requireOpaque(p.rawOpaque) }},
		{"overlay-remount", func() error { return mountOverlay(p) }},
		{"overlay-remount-view", func() error { return checkFinalView(p) }},
		{"overlay-remount-umount", unmountOverlay},
	}
}

// makeLower mounts a private tmpfs with the lower files.
func makeLower() error {
	if err := os.MkdirAll(overlayLowerDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(overlayMergedDir, 0o755); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", overlayLowerDir, "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("mount the lower tmpfs: %w", err)
	}
	for name, data := range lowerFiles {
		path := filepath.Join(overlayLowerDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// makeLowerOnce builds the lower layer when no earlier step built it.
func makeLowerOnce() error {
	if _, err := os.Stat(overlayLowerDir + "/keep"); err == nil {
		return nil
	}
	return makeLower()
}

func mountOverlay(p overlayUpperPaths) error {
	if err := makeLowerOnce(); err != nil {
		return err
	}
	for _, d := range []string{p.upper, p.work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	opts := "lowerdir=" + overlayLowerDir + ",upperdir=" + p.upper + ",workdir=" + p.work
	if err := syscall.Mount("overlay", overlayMergedDir, "overlay", 0, opts); err != nil {
		return fmt.Errorf("mount overlay (%s): %w", opts, err)
	}
	return nil
}

// refuseProcUpper mounts an overlay with a procfs upper layer. Only the
// filesystems with whiteouts and overlay xattrs may serve as an upper layer, so
// the mount must fail with EINVAL.
func refuseProcUpper() error {
	if err := makeLowerOnce(); err != nil {
		return err
	}
	opts := "lowerdir=" + overlayLowerDir + ",upperdir=/proc,workdir=/proc"
	err := syscall.Mount("overlay", overlayMergedDir, "overlay", 0, opts)
	if err == nil {
		syscall.Unmount(overlayMergedDir, 0)
		return errors.New("an overlay with a procfs upper layer mounted")
	}
	if !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("mount with a procfs upper layer: %w, want EINVAL", err)
	}
	return nil
}

func unmountOverlay() error {
	if err := syscall.Unmount(overlayMergedDir, 0); err != nil {
		return fmt.Errorf("unmount overlay: %w", err)
	}
	return nil
}

// statWhiteout fails unless path is a character device with the device number
// 0:0. It uses lstat, so it does not follow a symbolic link.
func statWhiteout(path string) error {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return fmt.Errorf("%s has mode %#o, want a character device", path, st.Mode)
	}
	if st.Rdev != 0 {
		return fmt.Errorf("%s has rdev %#x, want 0:0", path, st.Rdev)
	}
	return nil
}

func rawWhiteoutCreate(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := syscall.Mknod(path, syscall.S_IFCHR|0o000, 0); err != nil {
		return fmt.Errorf("mknod c 0:0: %w", err)
	}
	return statWhiteout(path)
}

func rawOpaqueCreate(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	if err := syscall.Setxattr(path, opaqueXattr, []byte("y"), 0); err != nil {
		return fmt.Errorf("set %s: %w", opaqueXattr, err)
	}
	return requireOpaque(path)
}

// requireOpaque reads the opaque xattr through getxattr and listxattr.
func requireOpaque(path string) error {
	buf := make([]byte, 16)
	n, err := syscall.Getxattr(path, opaqueXattr, buf)
	if err != nil {
		return fmt.Errorf("get %s of %s: %w", opaqueXattr, path, err)
	}
	if string(buf[:n]) != "y" {
		return fmt.Errorf("%s of %s = %q, want y", opaqueXattr, path, buf[:n])
	}
	list := make([]byte, 1024)
	n, err = syscall.Listxattr(path, list)
	if err != nil {
		return fmt.Errorf("list xattrs of %s: %w", path, err)
	}
	if !bytes.Contains(append([]byte{0}, list[:n]...), []byte("\x00"+opaqueXattr+"\x00")) {
		return fmt.Errorf("listxattr of %s = %q, want %s in it", path, list[:n], opaqueXattr)
	}
	return nil
}

func merged(name string) string { return filepath.Join(overlayMergedDir, name) }

func readString(path string) (string, error) {
	data, err := os.ReadFile(path)
	return string(data), err
}

func requireContent(path, want string) error {
	got, err := readString(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s = %q, want %q", path, got, want)
	}
	return nil
}

func requireMissing(path string) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lstat %s = %v, want ENOENT", path, err)
	}
	return nil
}

func requireNames(dir string, want ...string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return fmt.Errorf("entries of %s = %v, want %v", dir, got, want)
	}
	return nil
}

// requireRegular fails unless path is a regular file. It uses lstat.
func requireRegular(path string) error {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fmt.Errorf("%s has mode %#o, want a regular file", path, st.Mode)
	}
	return nil
}

func checkInitialView() error {
	return requireNames(overlayMergedDir, "del", "recreate", "gone", "src2", "cu", "hl", "keep", "dir", "stay", "Mixed", "mixed", "con", "q?x")
}

// overlayDelete removes a lower file. The merged view hides it, the upper
// layer holds a whiteout, and the lower layer keeps the file.
func overlayDelete(p overlayUpperPaths) error {
	for range 2 {
		if _, err := os.Stat(merged("del")); err != nil {
			return err
		}
	}
	if err := os.Remove(merged("del")); err != nil {
		return err
	}
	if err := requireMissing(merged("del")); err != nil {
		return err
	}
	if err := statWhiteout(filepath.Join(p.upper, "del")); err != nil {
		return fmt.Errorf("upper layer: %w", err)
	}
	if err := requireContent(overlayLowerDir+"/del", lowerFiles["del"]); err != nil {
		return err
	}
	if _, err := os.Stat(merged("recreate")); err != nil {
		return err
	}
	if err := os.Remove(merged("recreate")); err != nil {
		return err
	}
	return requireMissing(merged("recreate"))
}

func overlayRecreate() error {
	if err := os.WriteFile(merged("recreate"), []byte("new content\n"), 0o644); err != nil {
		return err
	}
	return requireContent(merged("recreate"), "new content\n")
}

// overlayRenameOverDeleted renames a new file onto the name of a deleted lower
// file.
func overlayRenameOverDeleted() error {
	if err := os.Remove(merged("gone")); err != nil {
		return err
	}
	if err := os.WriteFile(merged("fresh"), []byte("renamed fresh\n"), 0o644); err != nil {
		return err
	}
	if err := os.Rename(merged("fresh"), merged("gone")); err != nil {
		return err
	}
	if err := requireMissing(merged("fresh")); err != nil {
		return err
	}
	return requireContent(merged("gone"), "renamed fresh\n")
}

// overlayRenameLower renames a lower file. The old name must show no file, and
// the new name must show the lower content.
func overlayRenameLower() error {
	if err := os.Rename(merged("src2"), merged("moved")); err != nil {
		return err
	}
	if err := requireMissing(merged("src2")); err != nil {
		return err
	}
	return requireContent(merged("moved"), lowerFiles["src2"])
}

// overlayOpaqueDir removes a lower directory and creates a directory with the
// same name. No lower entry may show in the new directory.
func overlayOpaqueDir() error {
	if _, err := os.ReadDir(merged("dir")); err != nil {
		return err
	}
	if err := os.RemoveAll(merged("dir")); err != nil {
		return err
	}
	if err := requireMissing(merged("dir")); err != nil {
		return err
	}
	if err := os.Mkdir(merged("dir"), 0o755); err != nil {
		return err
	}
	if err := requireNames(merged("dir")); err != nil {
		return err
	}
	if err := os.WriteFile(merged("dir/new"), []byte("n\n"), 0o644); err != nil {
		return err
	}
	return requireNames(merged("dir"), "new")
}

// overlayCopyUp appends to a lower file. The merged file shows both parts and
// the lower file stays as it was.
func overlayCopyUp() error {
	f, err := os.OpenFile(merged("cu"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString("appended\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := requireContent(merged("cu"), lowerFiles["cu"]+"appended\n"); err != nil {
		return err
	}
	return requireContent(overlayLowerDir+"/cu", lowerFiles["cu"])
}

// overlayHardlink links a lower file, which copies it up. A write through one
// name shows through the other name.
func overlayHardlink() error {
	if err := os.Link(merged("hl"), merged("hl2")); err != nil {
		return err
	}
	f, err := os.OpenFile(merged("hl2"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString("via hl2\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return requireContent(merged("hl"), lowerFiles["hl"]+"via hl2\n")
}

// overlayAwkwardNames deletes lower files whose names a host can fold or
// refuse. Only the deleted name may vanish. A new file whose name differs from
// a lower name only in case must coexist with it.
func overlayAwkwardNames() error {
	for _, name := range []string{"Mixed", "con", "q?x"} {
		if err := os.Remove(merged(name)); err != nil {
			return err
		}
		if err := requireMissing(merged(name)); err != nil {
			return err
		}
	}
	if err := requireContent(merged("mixed"), lowerFiles["mixed"]); err != nil {
		return err
	}
	if err := os.WriteFile(merged("MIXED"), []byte("upper MIXED\n"), 0o644); err != nil {
		return err
	}
	return requireContent(merged("MIXED"), "upper MIXED\n")
}

// overlayExecFromLayers copies the probe into the lower layer and the upper
// layer of a second overlay on the same filesystem. It runs each copy several
// times through the overlay. Each run maps the executable and unmaps it at
// exit, and the next run must map it again.
func overlayExecFromLayers(p overlayUpperPaths) error {
	exe, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return err
	}
	base := filepath.Dir(p.upper)
	lower := filepath.Join(base, "exec-lower")
	upper := filepath.Join(base, "exec-upper")
	work := filepath.Join(base, "exec-work")
	for _, d := range []string{lower, upper, work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(lower, "app"), exe, 0o755); err != nil {
		return err
	}
	const mnt = "/ovl/exec"
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		return err
	}
	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := syscall.Mount("overlay", mnt, "overlay", 0, opts); err != nil {
		return fmt.Errorf("mount overlay (%s): %w", opts, err)
	}
	defer syscall.Unmount(mnt, 0)
	run := func(stage string) error {
		for i := range 3 {
			out, err := exec.Command(mnt+"/app", "ids").CombinedOutput()
			if err != nil || !bytes.HasPrefix(out, []byte("uid=")) {
				return fmt.Errorf("%s, run %d of the executable: %v, output %q", stage, i+1, err, out)
			}
		}
		return nil
	}
	if err := run("lower layer"); err != nil {
		return err
	}
	// A mode change copies the file up. The copy lives in the upper layer.
	if err := os.Chmod(mnt+"/app", 0o700); err != nil {
		return err
	}
	return run("upper layer")
}

// checkFinalView verifies the merged view, the raw upper layer, and the lower
// layer after every overlay write.
func checkFinalView(p overlayUpperPaths) error {
	if err := requireNames(overlayMergedDir, "recreate", "gone", "moved", "cu", "hl", "hl2", "keep", "dir", "stay", "mixed", "MIXED"); err != nil {
		return err
	}
	for _, name := range []string{"del", "src2", "fresh", "dir/a", "dir/b", "dir/sub", "Mixed", "con", "q?x"} {
		if err := requireMissing(merged(name)); err != nil {
			return err
		}
	}
	for name, want := range map[string]string{
		"recreate": "new content\n",
		"gone":     "renamed fresh\n",
		"moved":    lowerFiles["src2"],
		"cu":       lowerFiles["cu"] + "appended\n",
		"hl":       lowerFiles["hl"] + "via hl2\n",
		"hl2":      lowerFiles["hl"] + "via hl2\n",
		"keep":     lowerFiles["keep"],
		"stay/x":   lowerFiles["stay/x"],
		"dir/new":  "n\n",
		"mixed":    lowerFiles["mixed"],
		"MIXED":    "upper MIXED\n",
	} {
		if err := requireContent(merged(name), want); err != nil {
			return err
		}
	}
	if err := requireNames(merged("dir"), "new"); err != nil {
		return err
	}
	var hl, hl2 syscall.Stat_t
	if err := syscall.Stat(merged("hl"), &hl); err != nil {
		return err
	}
	if err := syscall.Stat(merged("hl2"), &hl2); err != nil {
		return err
	}
	if hl.Ino != hl2.Ino || hl.Nlink != 2 || hl2.Nlink != 2 {
		return fmt.Errorf("hard link: hl = (ino %d, nlink %d), hl2 = (ino %d, nlink %d), want one inode with 2 links", hl.Ino, hl.Nlink, hl2.Ino, hl2.Nlink)
	}

	for _, name := range []string{"del", "src2", "Mixed", "con", "q?x"} {
		if err := statWhiteout(filepath.Join(p.upper, name)); err != nil {
			return fmt.Errorf("upper layer: %w", err)
		}
	}
	for _, name := range []string{"recreate", "gone", "moved", "cu", "hl", "hl2", "MIXED"} {
		if err := requireRegular(filepath.Join(p.upper, name)); err != nil {
			return fmt.Errorf("upper layer: %w", err)
		}
	}
	if err := requireOpaque(filepath.Join(p.upper, "dir")); err != nil {
		return fmt.Errorf("upper layer: %w", err)
	}
	if err := requireMissing(filepath.Join(p.upper, "dir/a")); err != nil {
		return fmt.Errorf("upper layer: %w", err)
	}
	for name, want := range lowerFiles {
		if err := requireContent(filepath.Join(overlayLowerDir, name), want); err != nil {
			return fmt.Errorf("lower layer: %w", err)
		}
	}
	return nil
}

// syncUpper flushes the upper tree so that a SIGKILL of the host process
// leaves it on disk. It syncs each file and directory, then the whole mount.
func syncUpper(dir string) error {
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := f.Sync(); err != nil {
			return fmt.Errorf("fsync %s: %w", path, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	syscall.Sync()
	return nil
}
