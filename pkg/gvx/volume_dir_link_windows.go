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

package gvx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// createLegacyVolumeLink creates an NTFS directory junction at legacy pointing
// to root so earlier gvx releases reach the migrated volume directory without
// requiring administrator privileges or Windows Developer Mode. If junction
// creation fails (for example on a UNC target or a filesystem without reparse
// points), it falls back to os.Symlink.
func createLegacyVolumeLink(legacy, root string) error {
	if err := createDirectoryJunction(legacy, root); err == nil {
		return nil
	}
	return os.Symlink(root, legacy)
}

// createDirectoryJunction stages the reparse point in a private sibling temp
// directory and publishes it atomically via MoveFileEx without overwrite flags,
// so no transient empty regular directory ever appears at linkPath.
func createDirectoryJunction(linkPath, target string) error {
	data, err := buildMountPointReparseData(target)
	if err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp(filepath.Dir(linkPath), ".gvx-junction-*")
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = os.Remove(tmpDir)
		}
	}()

	tmpPtr, err := windows.UTF16PtrFromString(tmpDir)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(
		tmpPtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	var bytesReturned uint32
	ioctlErr := windows.DeviceIoControl(
		h,
		windows.FSCTL_SET_REPARSE_POINT,
		&data[0],
		uint32(len(data)),
		nil,
		0,
		&bytesReturned,
		nil,
	)
	closeErr := windows.CloseHandle(h)
	if ioctlErr != nil {
		return ioctlErr
	}
	if closeErr != nil {
		return closeErr
	}

	linkPtr, err := windows.UTF16PtrFromString(linkPath)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(tmpPtr, linkPtr, 0); err != nil {
		return err
	}
	published = true
	return nil
}

// buildMountPointReparseData encodes a Windows REPARSE_DATA_BUFFER for
// IO_REPARSE_TAG_MOUNT_POINT targeting a local volume path. NTFS junctions
// cannot target UNC network shares, so UNC targets return an error to trigger
// the os.Symlink fallback.
func buildMountPointReparseData(target string) ([]byte, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	if strings.ContainsRune(abs, 0) {
		return nil, errors.New("gvx: junction target contains NUL byte")
	}

	var printName string
	switch {
	case len(abs) >= 8 && strings.EqualFold(abs[:8], `\\?\UNC\`):
		return nil, errors.New("gvx: NTFS directory junctions do not support UNC targets")
	case strings.HasPrefix(abs, `\\?\`):
		printName = strings.TrimPrefix(abs, `\\?\`)
	case strings.HasPrefix(abs, `\\`):
		return nil, errors.New("gvx: NTFS directory junctions do not support UNC targets")
	default:
		printName = abs
	}
	subName := `\??\` + printName

	subUTF16 := utf16.Encode([]rune(subName))
	printUTF16 := utf16.Encode([]rune(printName))
	subBytes := len(subUTF16) * 2
	printOff := (len(subUTF16) + 1) * 2
	printBytes := len(printUTF16) * 2
	reparseDataLen := 8 + (len(subUTF16)+1+len(printUTF16)+1)*2
	totalLen := 8 + reparseDataLen
	if reparseDataLen > math.MaxUint16 || totalLen > windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE {
		return nil, fmt.Errorf("gvx: junction reparse buffer size %d exceeds limit", totalLen)
	}

	buf := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(buf[0:4], windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(reparseDataLen))
	binary.LittleEndian.PutUint16(buf[6:8], 0)
	binary.LittleEndian.PutUint16(buf[8:10], 0)
	binary.LittleEndian.PutUint16(buf[10:12], uint16(subBytes))
	binary.LittleEndian.PutUint16(buf[12:14], uint16(printOff))
	binary.LittleEndian.PutUint16(buf[14:16], uint16(printBytes))

	for i, u := range subUTF16 {
		binary.LittleEndian.PutUint16(buf[16+i*2:], u)
	}
	for i, u := range printUTF16 {
		binary.LittleEndian.PutUint16(buf[16+printOff+i*2:], u)
	}
	return buf, nil
}
