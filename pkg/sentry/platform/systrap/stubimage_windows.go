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
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// stubImageNamePrefix starts the name of every stub image file. The sweep of
// old files depends on it.
const stubImageNamePrefix = "gvx-stub-"

// volumeNameDOS asks GetFinalPathNameByHandle for a path with a drive letter.
const volumeNameDOS = 0

// stubImageMaxAge is the age at which the sweep removes a stub image that a
// crashed host left behind. A live host holds its file open, so the sweep could
// not delete it. The age keeps the sweep away from the file of a host that is
// still between the write and the lock.
const stubImageMaxAge = 10 * time.Minute

// stubImage is the executable file that the stub processes run. The host writes
// the file once, then holds a handle that shares read access only. While the
// handle is open, no process can open the file for write or delete, or rename
// it. The loader reads the file through its own handle, which asks for read
// access, so the lock and the loader do not conflict.
type stubImage struct {
	// path is the canonical path of the locked file.
	path string
	file windows.Handle
}

// stubImageMachine returns the machine field of the host architecture.
func stubImageMachine() uint16 {
	if runtime.GOARCH == "arm64" {
		return peMachineARM64
	}
	return peMachineAMD64
}

// createStubImage writes the image into dir and locks it. It verifies through
// the locked handle that the bytes are the bytes that it wrote. A process that
// replaced the file before the lock cannot make the host run other code.
func createStubImage(dir string) (*stubImage, error) {
	sweepStubImages(dir)
	var tag [8]byte
	if _, err := rand.Read(tag[:]); err != nil {
		return nil, fmt.Errorf("name the stub image: %w", err)
	}
	path := filepath.Join(dir, fmt.Sprintf("%s%d-%x.exe", stubImageNamePrefix, os.Getpid(), tag))
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	want := buildStubImage(stubImageMachine())

	// CREATE_NEW fails when the name exists, so the host never writes through a
	// file or link that another process planted. The write handle shares nothing.
	w, err := windows.CreateFile(path16, windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("create the stub image: %w", err)
	}
	var written windows.ByHandleFileInformation
	_, werr := windows.Write(w, want)
	if werr == nil {
		werr = windows.GetFileInformationByHandle(w, &written)
	}
	if cerr := windows.CloseHandle(w); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = windows.DeleteFile(path16)
		return nil, fmt.Errorf("write the stub image: %w", werr)
	}

	// The file is open to others between the close and the lock. The checks after
	// the lock cover that gap.
	r, err := windows.CreateFile(path16, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		_ = windows.DeleteFile(path16)
		return nil, fmt.Errorf("lock the stub image: %w", err)
	}
	img := &stubImage{file: r}
	if err := img.verify(&written, want); err != nil {
		img.file = 0
		_ = windows.CloseHandle(r)
		_ = windows.DeleteFile(path16)
		return nil, err
	}
	canonical, err := finalPath(r)
	if err != nil {
		img.file = 0
		_ = windows.CloseHandle(r)
		_ = windows.DeleteFile(path16)
		return nil, err
	}
	img.path = canonical
	return img, nil
}

// verify checks that the locked file is the file that the host wrote.
func (s *stubImage) verify(written *windows.ByHandleFileInformation, want []byte) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(s.file, &info); err != nil {
		return fmt.Errorf("query the stub image: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("the stub image is a reparse point")
	}
	if info.VolumeSerialNumber != written.VolumeSerialNumber ||
		info.FileIndexHigh != written.FileIndexHigh || info.FileIndexLow != written.FileIndexLow {
		return errors.New("another process replaced the stub image before the lock")
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("the stub image has %d links", info.NumberOfLinks)
	}
	got := make([]byte, len(want)+1)
	n, err := windows.Read(s.file, got)
	if err != nil {
		return fmt.Errorf("read the stub image: %w", err)
	}
	if !bytes.Equal(got[:n], want) {
		return errors.New("another process changed the stub image before the lock")
	}
	return nil
}

// close unlocks the file and removes it. A stub that still maps the image keeps
// the file on disk. The next sweep removes it.
func (s *stubImage) close() {
	if s == nil || s.file == 0 {
		return
	}
	_ = windows.CloseHandle(s.file)
	s.file = 0
	if p, err := windows.UTF16PtrFromString(s.path); err == nil {
		_ = windows.DeleteFile(p)
	}
}

// finalPath returns the path that the kernel resolved for h, without the
// extended-length prefix.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), volumeNameDOS)
		if err != nil {
			return "", fmt.Errorf("resolve the stub image path: %w", err)
		}
		if int(n) < len(buf) {
			return strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`), nil
		}
		buf = make([]uint16, n+1)
	}
}

// sweepStubImages removes the files that crashed hosts left in dir. It ignores
// every error, because the files are only litter.
func sweepStubImages(dir string) {
	pattern, err := windows.UTF16PtrFromString(filepath.Join(dir, stubImageNamePrefix+"*.exe"))
	if err != nil {
		return
	}
	var data windows.Win32finddata
	find, err := windows.FindFirstFile(pattern, &data)
	if err != nil {
		return
	}
	defer windows.FindClose(find)
	cutoff := time.Now().Add(-stubImageMaxAge).UnixNano()
	for {
		if data.LastWriteTime.Nanoseconds() < cutoff {
			name := windows.UTF16ToString(data.FileName[:])
			if p, err := windows.UTF16PtrFromString(filepath.Join(dir, name)); err == nil {
				_ = windows.DeleteFile(p)
			}
		}
		if err := windows.FindNextFile(find, &data); err != nil {
			return
		}
	}
}
