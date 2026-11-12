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
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createSizedTempFile(t *testing.T, dir, name string, size int) windows.Handle {
	t.Helper()
	pathPtr, err := windows.UTF16PtrFromString(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_TEMPORARY|windows.FILE_FLAG_DELETE_ON_CLOSE,
		0,
	)
	if err != nil {
		t.Fatalf("CreateFile(%s): %v", name, err)
	}
	buf := make([]byte, size)
	var written uint32
	if err := windows.WriteFile(h, buf, &written, nil); err != nil {
		_ = windows.CloseHandle(h)
		t.Fatalf("WriteFile(%s): %v", name, err)
	}
	return h
}

func TestSectionCacheDistinguishesClosedAndReusedHandle(t *testing.T) {
	dir := t.TempDir()
	var sc sectionCache
	defer sc.close()

	h1 := createSizedTempFile(t, dir, "file1.bin", blockSize)
	ref1, err := sc.get(h1, blockSize, true)
	if err != nil {
		_ = windows.CloseHandle(h1)
		t.Fatalf("sc.get(h1): %v", err)
	}
	_ = windows.CloseHandle(h1)

	var h2 windows.Handle
	for i := range 64 {
		cand := createSizedTempFile(t, dir, fmt.Sprintf("reopen-%d.bin", i), blockSize)
		if cand == h1 {
			h2 = cand
			break
		}
		_ = windows.CloseHandle(cand)
	}
	if h2 == 0 {
		t.Skip("Windows did not reassign the closed handle slot within 64 opens")
	}
	defer func() { _ = windows.CloseHandle(h2) }()

	const want = uint64(0x1122_3344_5566_7788)
	const off = 0x50F
	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], want)
	var ov windows.Overlapped
	ov.Offset = off
	var written uint32
	if err := windows.WriteFile(h2, payload[:], &written, &ov); err != nil || written != 8 {
		t.Fatalf("WriteFile(h2) = (%d, %v), want 8 bytes", written, err)
	}

	ref2, err := sc.get(h2, blockSize, true)
	if err != nil {
		t.Fatalf("sc.get(h2): %v", err)
	}
	if ref2 == ref1 || ref2.h == ref1.h || ref2.file == ref1.file {
		t.Fatalf("sectionCache reused stale section on reassigned handle %#x: ref1=%+v ref2=%+v", h2, ref1, ref2)
	}

	addr, err := windows.MapViewOfFile(ref2.h, windows.FILE_MAP_READ, 0, 0, blockSize)
	if err != nil {
		t.Fatalf("MapViewOfFile(ref2): %v", err)
	}
	defer func() { _ = windows.UnmapViewOfFile(addr) }()
	view := unsafe.Slice((*byte)(addrPtr(uint64(addr))), blockSize)
	if got := binary.LittleEndian.Uint64(view[off:]); got != want {
		t.Fatalf("mapped view at %#x = %#x, want %#x", off, got, want)
	}
}
