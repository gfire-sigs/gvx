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

//go:build windows

package systrap

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runImage starts path as a normal process and returns its exit code.
func runImage(t *testing.T, path string) uint32 {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(p, nil, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi); err != nil {
		t.Fatalf("CreateProcess(%s): %v", path, err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	if ev, err := windows.WaitForSingleObject(pi.Process, 20000); err != nil || ev != windows.WAIT_OBJECT_0 {
		t.Fatalf("WaitForSingleObject = %d, %v", ev, err)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		t.Fatal(err)
	}
	return code
}

// The loader of Windows 11 fails an image without a valid load configuration
// with 0xC000007B. Only a real process start proves that the header is right.
func TestStubImageRunsAsAProcess(t *testing.T) {
	img, err := createStubImage(t.TempDir())
	if err != nil {
		t.Fatalf("createStubImage: %v", err)
	}
	defer img.close()
	if code := runImage(t, img.path); code != 0 {
		t.Fatalf("the stub image exited with %#x, want 0. A code of 0xC000007B means that the loader rejected the header", code)
	}
}

// The host must run the bytes that it wrote. While the host holds the file, no
// other process may open it for write or delete, or rename it. The loader must
// still read it.
func TestStubImageLockRefusesWritersAndAllowsReaders(t *testing.T) {
	dir := t.TempDir()
	img, err := createStubImage(dir)
	if err != nil {
		t.Fatalf("createStubImage: %v", err)
	}
	defer img.close()
	p, _ := windows.UTF16PtrFromString(img.path)

	for _, access := range []struct {
		name string
		bits uint32
	}{{"write", windows.GENERIC_WRITE}, {"append", windows.FILE_APPEND_DATA}, {"delete", windows.DELETE}} {
		h, err := windows.CreateFile(p, access.bits, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			windows.CloseHandle(h)
			t.Errorf("open for %s succeeded while the host holds the image", access.name)
		} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Errorf("open for %s failed with %v, want a sharing violation", access.name, err)
		}
	}
	if err := os.Remove(img.path); err == nil {
		t.Error("os.Remove deleted the locked image")
	}
	if err := os.Rename(img.path, filepath.Join(dir, "other.exe")); err == nil {
		t.Error("os.Rename moved the locked image")
	}
	if err := os.WriteFile(img.path, []byte("x"), 0o755); err == nil {
		t.Error("os.WriteFile replaced the locked image")
	}
	// Record whether the directory of a locked file can be renamed. The threat
	// model in the document depends on the answer.
	moved := dir + "-moved"
	if err := os.Rename(dir, moved); err == nil {
		t.Logf("DIRECTORY RENAME OF A LOCKED FILE SUCCEEDED")
		_ = os.Rename(moved, dir)
	} else {
		t.Logf("directory rename of a locked file failed: %v", err)
	}
	if got := runImage(t, img.path); got != 0 {
		t.Errorf("the loader could not run the locked image: exit %#x", got)
	}
}

func TestStubImageCloseRemovesTheFile(t *testing.T) {
	img, err := createStubImage(t.TempDir())
	if err != nil {
		t.Fatalf("createStubImage: %v", err)
	}
	path := img.path
	img.close()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("after close, Stat(%s) = %v, want not exist", path, err)
	}
	img.close()
}

func TestSweepRemovesOldStubImagesOnly(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, stubImageNamePrefix+"1-old.exe")
	young := filepath.Join(dir, stubImageNamePrefix+"2-young.exe")
	other := filepath.Join(dir, "unrelated.exe")
	for _, p := range []string{old, young, other} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * stubImageMaxAge)
	for _, p := range []string{old, other} {
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	sweepStubImages(dir)
	for p, wantGone := range map[string]bool{old: true, young: false, other: false} {
		_, err := os.Stat(p)
		if gone := errors.Is(err, os.ErrNotExist); gone != wantGone {
			t.Errorf("%s: removed = %v, want %v", filepath.Base(p), gone, wantGone)
		}
	}
}

// The path must have a drive letter and no extended-length prefix, so that the
// command line of CreateProcess accepts it.
func TestStubImagePathIsPlain(t *testing.T) {
	img, err := createStubImage(t.TempDir())
	if err != nil {
		t.Fatalf("createStubImage: %v", err)
	}
	defer img.close()
	if strings.HasPrefix(img.path, `\\`) || !filepath.IsAbs(img.path) {
		t.Fatalf("path = %q, want an absolute path with a drive letter", img.path)
	}
}
