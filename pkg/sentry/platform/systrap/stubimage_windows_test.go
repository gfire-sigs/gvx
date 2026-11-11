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
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// verifyLockedStubImageInvariants opens img.path with GENERIC_READ and FILE_SHARE_READ
// while img.file holds the read-only lock, and verifies the on-disk PE header, section
// alignment, entry/trap page RVA offsets, and file-handle identity invariants.
func verifyLockedStubImageInvariants(t *testing.T, img *stubImage) {
	t.Helper()
	if img.file == 0 {
		t.Fatal("img.file = 0, want valid locked handle")
	}
	path16, err := windows.UTF16PtrFromString(img.path)
	if err != nil {
		t.Fatalf("UTF16PtrFromString(%q): %v", img.path, err)
	}
	reader, err := windows.CreateFile(
		path16,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatalf("concurrent GENERIC_READ open of locked stub image failed: %v", err)
	}
	defer windows.CloseHandle(reader)

	var lockedInfo, readerInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(img.file, &lockedInfo); err != nil {
		t.Fatalf("GetFileInformationByHandle(img.file): %v", err)
	}
	if err := windows.GetFileInformationByHandle(reader, &readerInfo); err != nil {
		t.Fatalf("GetFileInformationByHandle(reader): %v", err)
	}
	if lockedInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatalf("locked stub image has FILE_ATTRIBUTE_REPARSE_POINT: %#x", lockedInfo.FileAttributes)
	}
	if lockedInfo.NumberOfLinks != 1 {
		t.Fatalf("lockedInfo.NumberOfLinks = %d, want 1", lockedInfo.NumberOfLinks)
	}
	if lockedInfo.VolumeSerialNumber != readerInfo.VolumeSerialNumber ||
		lockedInfo.FileIndexHigh != readerInfo.FileIndexHigh ||
		lockedInfo.FileIndexLow != readerInfo.FileIndexLow {
		t.Fatalf("reader handle file identity (%#x:%#x:%#x) != locked handle (%#x:%#x:%#x)",
			readerInfo.VolumeSerialNumber, readerInfo.FileIndexHigh, readerInfo.FileIndexLow,
			lockedInfo.VolumeSerialNumber, lockedInfo.FileIndexHigh, lockedInfo.FileIndexLow)
	}

	wantBytes := buildStubImage(stubImageMachine())
	diskBytes := make([]byte, len(wantBytes)+16)
	n, err := windows.Read(reader, diskBytes)
	if err != nil {
		t.Fatalf("Read(reader): %v", err)
	}
	diskBytes = diskBytes[:n]
	if n != stubImageSize || !bytes.Equal(diskBytes, wantBytes) {
		t.Fatalf("on-disk stub image size = %d (want %d), bytes match = %v", n, stubImageSize, bytes.Equal(diskBytes, wantBytes))
	}

	peFile, err := pe.NewFile(bytes.NewReader(diskBytes))
	if err != nil {
		t.Fatalf("pe.NewFile(diskBytes): %v", err)
	}
	if peFile.Machine != stubImageMachine() {
		t.Fatalf("PE Machine = %#x, want %#x", peFile.Machine, stubImageMachine())
	}
	oh, ok := peFile.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("OptionalHeader = %T, want *pe.OptionalHeader64", peFile.OptionalHeader)
	}
	if oh.SectionAlignment != peSectionAlign || oh.FileAlignment != peFileAlign {
		t.Fatalf("SectionAlignment=%#x FileAlignment=%#x, want %#x and %#x",
			oh.SectionAlignment, oh.FileAlignment, uint32(peSectionAlign), uint32(peFileAlign))
	}
	if oh.ImageBase != peImageBase {
		t.Fatalf("ImageBase = %#x, want %#x", oh.ImageBase, uint64(peImageBase))
	}
	if oh.AddressOfEntryPoint != peSectionAlign || oh.BaseOfCode != peSectionAlign {
		t.Fatalf("AddressOfEntryPoint=%#x BaseOfCode=%#x, want %#x",
			oh.AddressOfEntryPoint, oh.BaseOfCode, uint32(peSectionAlign))
	}
	if len(peFile.Sections) != 1 {
		t.Fatalf("len(Sections) = %d, want 1", len(peFile.Sections))
	}
	sec := peFile.Sections[0]
	if sec.VirtualAddress != peSectionAlign || sec.Offset != peFileAlign || sec.Size != peFileAlign {
		t.Fatalf(".text section VA=%#x Offset=%#x Size=%#x, want VA=%#x Offset=%#x Size=%#x",
			sec.VirtualAddress, sec.Offset, sec.Size, uint32(peSectionAlign), uint32(peFileAlign), uint32(peFileAlign))
	}
	relocDir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if relocDir.VirtualAddress != peSectionAlign+stubImageRelocOff || relocDir.Size != 8 {
		t.Fatalf("base reloc directory = %+v, want VA=%#x Size=8", relocDir, uint32(peSectionAlign+stubImageRelocOff))
	}
	loadDir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
	if loadDir.VirtualAddress != peSectionAlign+stubImageLoadOff || loadDir.Size != stubImageLoadSize {
		t.Fatalf("load config directory = %+v, want VA=%#x Size=%#x",
			loadDir, uint32(peSectionAlign+stubImageLoadOff), uint32(stubImageLoadSize))
	}
	guardFlags := binary.LittleEndian.Uint32(diskBytes[peFileAlign+stubImageLoadOff+loadConfigGuardFlagsOff:])
	if guardFlags&guardSecurityCookieUnused == 0 {
		t.Fatalf("GuardFlags = %#x, want bit %#x set", guardFlags, uint32(guardSecurityCookieUnused))
	}
}

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
	verifyLockedStubImageInvariants(t, img)
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
	verifyLockedStubImageInvariants(t, img)
	p, err := windows.UTF16PtrFromString(img.path)
	if err != nil {
		t.Fatalf("UTF16PtrFromString(%q): %v", img.path, err)
	}

	for _, access := range []struct {
		name string
		bits uint32
	}{
		{"write", windows.GENERIC_WRITE},
		{"append", windows.FILE_APPEND_DATA},
		{"delete", windows.DELETE},
	} {
		h, err := windows.CreateFile(p, access.bits, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			windows.CloseHandle(h)
			t.Errorf("open for %s succeeded while the host holds the image", access.name)
		} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Errorf("open for %s failed with %v, want a sharing violation", access.name, err)
		}
	}
	// Opening with write or delete sharing must also fail with ERROR_SHARING_VIOLATION
	// because the host handle shares only FILE_SHARE_READ.
	for _, share := range []struct {
		name string
		mode uint32
	}{
		{"share-write", windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE},
		{"share-delete", windows.FILE_SHARE_READ | windows.FILE_SHARE_DELETE},
	} {
		h, err := windows.CreateFile(p, windows.GENERIC_READ, share.mode,
			nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			windows.CloseHandle(h)
			t.Errorf("GENERIC_READ open with %s succeeded while the host holds the image", share.name)
		} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Errorf("GENERIC_READ open with %s failed with %v, want ERROR_SHARING_VIOLATION", share.name, err)
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
	if got := runImage(t, img.path); got != 0 {
		t.Errorf("the loader could not run the locked image: exit %#x", got)
	}
	verifyLockedStubImageInvariants(t, img)
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
