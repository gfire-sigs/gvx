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

package hostfs

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/abi/linux"
)

// The portable tests of vfs_extended_ops_test.go run on Windows with the real
// capabilities of the volume. These tests check the Windows branches that
// no other host reaches.

func TestWindowsUsesTheTranslationPaths(t *testing.T) {
	e := newEnv(t)
	caps := e.ws.Caps()
	if caps.NativeRenameSwap {
		t.Fatal("NativeRenameSwap is true on Windows: NTFS has no atomic name swap")
	}
	if !caps.LocksOpenDirMove || e.ws.handles == nil {
		t.Fatalf("caps = %+v, handles = %v: Windows needs the open-handle registry", caps, e.ws.handles)
	}
}

// TestWindowsStatFSUsesDiskFreeSpace compares the guest numbers with
// GetDiskFreeSpaceEx for the workspace directory.
func TestWindowsStatFSUsesDiskFreeSpace(t *testing.T) {
	e := newEnv(t)
	path, err := windows.UTF16PtrFromString(e.dir + `\`)
	if err != nil {
		t.Fatal(err)
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(path, &avail, &total, &free); err != nil {
		t.Fatal(err)
	}
	st, err := e.vfsObj.StatFSAt(e.ctx, e.creds, e.fpop("."))
	if err != nil {
		t.Fatal(err)
	}
	if st.BlockSize != windowsBlockSize || st.Blocks != total/windowsBlockSize {
		t.Fatalf("guest volume = (block size %d, blocks %d), host total = %d bytes", st.BlockSize, st.Blocks, total)
	}
	if st.BlocksAvailable > st.BlocksFree || st.BlocksFree > st.Blocks {
		t.Fatalf("guest blocks free %d available %d total %d are not consistent", st.BlocksFree, st.BlocksAvailable, st.Blocks)
	}
}

// TestWindowsAllocateSetsTheAllocationSize checks that FileAllocationInfo
// reserves clusters without a change of the end of file, and that mode 0 moves
// the end of file as well.
func TestWindowsAllocateSetsTheAllocationSize(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", nil)
	fd := e.mustOpen("f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	standard := func() fileStandardInfo {
		t.Helper()
		f, err := os.Open(e.host("f"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		var info fileStandardInfo
		if err := windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), windows.FileStandardInfo,
			(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			t.Fatal(err)
		}
		return info
	}
	const reserve = 1 << 20
	if err := allocate(e, fd, keepSize, 0, reserve); err != nil {
		t.Fatalf("allocate with KEEP_SIZE: %v", err)
	}
	if info := standard(); info.EndOfFile != 0 || info.AllocationSize < reserve {
		t.Fatalf("after KEEP_SIZE: end of file %d, allocation size %d, want 0 and at least %d", info.EndOfFile, info.AllocationSize, reserve)
	}
	if err := allocate(e, fd, 0, 0, 2*reserve); err != nil {
		t.Fatalf("allocate mode 0: %v", err)
	}
	if info := standard(); info.EndOfFile != 2*reserve || info.AllocationSize < 2*reserve {
		t.Fatalf("after mode 0: end of file %d, allocation size %d, want %d", info.EndOfFile, info.AllocationSize, 2*reserve)
	}
	// A smaller request never shrinks the file.
	if err := allocate(e, fd, 0, 0, 4096); err != nil {
		t.Fatal(err)
	}
	if info := standard(); info.EndOfFile != 2*reserve {
		t.Fatalf("end of file after a smaller request = %d, want %d", info.EndOfFile, 2*reserve)
	}
}

// TestWindowsTmpfileKeepsANamedFileUntilRelease checks the named file of an
// O_TMPFILE description on Windows, and that the last close removes it while
// the share flags let the delete succeed.
func TestWindowsTmpfileKeepsANamedFileUntilRelease(t *testing.T) {
	for _, extra := range []uint32{linux.O_RDWR, linux.O_RDWR | linux.O_EXCL} {
		e := newEnv(t)
		fd := e.mustOpenTmp(".", extra)
		names := e.hostEntries(".")
		if len(names) != 1 || !isEphemeralName(names[0]) {
			t.Fatalf("host entries while the file is open = %v, want one internal name", names)
		}
		e.pwriteAt(fd, 0, "data")
		fd.DecRef(e.ctx)
		if names := e.hostEntries("."); len(names) != 0 {
			t.Fatalf("host entries after the last close = %v, want none", names)
		}
	}
}

// TestWindowsExchangeLeavesNoSwapFile checks that the three renames clean up
// after themselves, also while descendant handles are open.
func TestWindowsExchangeLeavesNoSwapFile(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("a")
	e.mustMkdir("b")
	e.writeFile("a/f", []byte("fa"))
	e.writeFile("b/g", []byte("gb"))
	fa := e.mustOpen("a/f", linux.O_RDWR)
	defer fa.DecRef(e.ctx)
	if err := e.renameFlags("a", "b", linux.RENAME_EXCHANGE); err != nil {
		t.Fatalf("exchange of directories with an open descendant: %v", err)
	}
	if got := e.readFile("b/f"); string(got) != "fa" {
		t.Fatalf("b/f = %q, want fa", got)
	}
	e.pwriteAt(fa, 0, "F")
	if got := e.hostRead("b/f"); got != "Fa" {
		t.Fatalf("host b/f = %q, want Fa", got)
	}
	for _, name := range e.hostEntries(".") {
		if isEphemeralName(name) {
			t.Fatalf("host entry %q is left behind", name)
		}
	}
}
