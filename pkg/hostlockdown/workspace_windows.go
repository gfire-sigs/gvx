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

package hostlockdown

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// brokerShareAll matches hostfs open sharing flags so POSIX rename and unlink work.
	brokerShareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

	// finalPathVolumeNT selects FILE_NAME_NORMALIZED (0x0) | VOLUME_NAME_NT (0x2).
	finalPathVolumeNT = 0x2
)

// brokerFileIDInfo matches FILE_ID_INFO.
type brokerFileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

// brokerAttrTagInfo matches FILE_ATTRIBUTE_TAG_INFO.
type brokerAttrTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

// fileIDKey identifies an open file or directory on a volume.
type fileIDKey struct {
	dev uint64
	id  [16]byte
}

// sealedDirMount holds the pre-lockdown identity and kernel path of one
// directory HostMount. Apply never modifies any NTFS DACL or SACL on disk.
type sealedDirMount struct {
	mountPath  string
	rootHandle windows.Handle
	rootKey    fileIDKey
	rootKeyOK  bool
	ntPath     string
	readOnly   bool
	knownDirs  map[fileIDKey]struct{}
}

// sealedFileMount holds the pre-lockdown parent identity and stored leaf name
// of one single-file HostMount. Apply never modifies any NTFS DACL or SACL on disk.
type sealedFileMount struct {
	mountPath    string
	parentPath   string
	parentHandle windows.Handle
	parentKey    fileIDKey
	parentKeyOK  bool
	parentNTPath string
	leafName     string
	readOnly     bool
}

// sealedMountSet holds all mounts pinned before hostlockdown.Apply() drops
// primary token privileges and lowers integrity.
type sealedMountSet struct {
	dirs  []sealedDirMount
	files []sealedFileMount
}

func (s *sealedMountSet) close() {
	if s == nil {
		return
	}
	for i := range s.dirs {
		if s.dirs[i].rootHandle != 0 && s.dirs[i].rootHandle != windows.InvalidHandle {
			_ = windows.CloseHandle(s.dirs[i].rootHandle)
			s.dirs[i].rootHandle = 0
		}
	}
	for i := range s.files {
		if s.files[i].parentHandle != 0 && s.files[i].parentHandle != windows.InvalidHandle {
			_ = windows.CloseHandle(s.files[i].parentHandle)
			s.files[i].parentHandle = 0
		}
	}
}

// pinHostMounts resolves symlinks and opens read-only directory handles for
// every HostMount without altering any security descriptor on the host volume.
func pinHostMounts(mounts []HostMount) (*sealedMountSet, []string, error) {
	set := &sealedMountSet{
		dirs:  make([]sealedDirMount, 0, len(mounts)),
		files: make([]sealedFileMount, 0),
	}
	mountsReal := make([]string, 0, len(mounts))
	for _, m := range mounts {
		real, err := resolveMount(m.Path)
		if err != nil {
			set.close()
			return nil, nil, err
		}
		mountsReal = append(mountsReal, real)
		if m.File {
			fm, err := pinSingleFileMount(real, m.ReadOnly)
			if err != nil {
				set.close()
				return nil, nil, err
			}
			set.files = append(set.files, fm)
			continue
		}
		dm, err := pinDirectoryMount(real, m.ReadOnly)
		if err != nil {
			set.close()
			return nil, nil, err
		}
		set.dirs = append(set.dirs, dm)
	}
	return set, mountsReal, nil
}

func pinDirectoryMount(real string, readOnly bool) (sealedDirMount, error) {
	name, err := windows.UTF16PtrFromString(real)
	if err != nil {
		return sealedDirMount{}, fmt.Errorf("hostlockdown: encode mount path %q: %w", real, err)
	}
	h, err := windows.CreateFile(
		name,
		windows.FILE_TRAVERSE|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES,
		brokerShareAll,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return sealedDirMount{}, fmt.Errorf("hostlockdown: open mount directory %q: %w", real, err)
	}
	var bhfi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &bhfi); err != nil {
		_ = windows.CloseHandle(h)
		return sealedDirMount{}, fmt.Errorf("hostlockdown: stat mount directory %q: %w", real, err)
	}
	if bhfi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		_ = windows.CloseHandle(h)
		return sealedDirMount{}, fmt.Errorf("hostlockdown: mount %q is not a directory", real)
	}
	key, keyOK := queryFileIDKey(h, bhfi)
	ntPath, err := queryFinalPath(h, finalPathVolumeNT)
	if err != nil && !keyOK {
		_ = windows.CloseHandle(h)
		return sealedDirMount{}, fmt.Errorf("hostlockdown: query mount identity %q: %w", real, err)
	}
	known := make(map[fileIDKey]struct{}, 8)
	if keyOK {
		known[key] = struct{}{}
	}
	return sealedDirMount{
		mountPath:  real,
		rootHandle: h,
		rootKey:    key,
		rootKeyOK:  keyOK,
		ntPath:     ntPath,
		readOnly:   readOnly,
		knownDirs:  known,
	}, nil
}

func pinSingleFileMount(real string, readOnly bool) (sealedFileMount, error) {
	targetUTF16, err := windows.UTF16PtrFromString(real)
	if err != nil {
		return sealedFileMount{}, fmt.Errorf("hostlockdown: encode file mount %q: %w", real, err)
	}
	fh, err := windows.CreateFile(
		targetUTF16,
		windows.FILE_READ_ATTRIBUTES,
		brokerShareAll,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return sealedFileMount{}, fmt.Errorf("hostlockdown: open file mount %q: %w", real, err)
	}
	var fileBHFI windows.ByHandleFileInformation
	statErr := windows.GetFileInformationByHandle(fh, &fileBHFI)
	_ = windows.CloseHandle(fh)
	if statErr != nil {
		return sealedFileMount{}, fmt.Errorf("hostlockdown: stat file mount %q: %w", real, statErr)
	}
	if fileBHFI.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return sealedFileMount{}, fmt.Errorf("hostlockdown: file mount %q is not a regular file", real)
	}

	dirPath, reqLeaf := filepath.Split(real)
	dirPath = filepath.Clean(dirPath)
	storedLeaf, err := storedLeafInDir(dirPath, reqLeaf)
	if err != nil {
		return sealedFileMount{}, err
	}
	if err := validateBrokerName(storedLeaf); err != nil {
		return sealedFileMount{}, fmt.Errorf("hostlockdown: invalid file mount leaf %q: %w", storedLeaf, err)
	}

	dirUTF16, err := windows.UTF16PtrFromString(dirPath)
	if err != nil {
		return sealedFileMount{}, fmt.Errorf("hostlockdown: encode file mount parent %q: %w", dirPath, err)
	}
	ph, err := windows.CreateFile(
		dirUTF16,
		windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES,
		brokerShareAll,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return sealedFileMount{}, fmt.Errorf("hostlockdown: open file mount parent %q: %w", dirPath, err)
	}
	var parentBHFI windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(ph, &parentBHFI); err != nil {
		_ = windows.CloseHandle(ph)
		return sealedFileMount{}, fmt.Errorf("hostlockdown: stat file mount parent %q: %w", dirPath, err)
	}
	parentKey, parentKeyOK := queryFileIDKey(ph, parentBHFI)
	parentNTPath, err := queryFinalPath(ph, finalPathVolumeNT)
	if err != nil && !parentKeyOK {
		_ = windows.CloseHandle(ph)
		return sealedFileMount{}, fmt.Errorf("hostlockdown: query file mount parent %q: %w", dirPath, err)
	}
	return sealedFileMount{
		mountPath:    real,
		parentPath:   dirPath,
		parentHandle: ph,
		parentKey:    parentKey,
		parentKeyOK:  parentKeyOK,
		parentNTPath: parentNTPath,
		leafName:     storedLeaf,
		readOnly:     readOnly,
	}, nil
}

func storedLeafInDir(dirPath, reqLeaf string) (string, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return "", fmt.Errorf("hostlockdown: list parent %q: %w", dirPath, err)
	}
	fold := ""
	for _, e := range entries {
		switch {
		case e.Name() == reqLeaf:
			return reqLeaf, nil
		case fold == "" && strings.EqualFold(e.Name(), reqLeaf):
			fold = e.Name()
		}
	}
	if fold != "" {
		return fold, nil
	}
	return "", fmt.Errorf("hostlockdown: %q not found in %q: %w", reqLeaf, dirPath, os.ErrNotExist)
}

func queryFileIDKey(handle windows.Handle, bhfi windows.ByHandleFileInformation) (fileIDKey, bool) {
	var info brokerFileIDInfo
	if err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err == nil {
		return fileIDKey{dev: info.VolumeSerialNumber, id: info.FileID}, true
	}
	fileIndex := uint64(bhfi.FileIndexHigh)<<32 | uint64(bhfi.FileIndexLow)
	if bhfi.VolumeSerialNumber == 0 && fileIndex == 0 {
		return fileIDKey{}, false
	}
	var key fileIDKey
	key.dev = uint64(bhfi.VolumeSerialNumber)
	for i := range 8 {
		key.id[i] = byte(fileIndex >> (8 * i))
	}
	return key, true
}

func queryFinalPath(handle windows.Handle, flags uint32) (string, error) {
	var stack [512]uint16
	buf := stack[:]
	for {
		n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), flags)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, int(n)+1)
	}
}

func queryAttrTag(handle windows.Handle) (attrs, tag uint32, err error) {
	var info brokerAttrTagInfo
	if err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		return 0, 0, err
	}
	return info.FileAttributes, info.ReparseTag, nil
}

// validateBrokerName rejects path separators, dot segments, NTFS alternate data
// stream colons, control bytes, trailing spaces or dots, and Win32 device names.
func validateBrokerName(name string) error {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) {
		return windows.ERROR_INVALID_NAME
	}
	for i := range len(name) {
		c := name[i]
		if c < 0x20 || strings.IndexByte(`\/:*?"<>|`, c) >= 0 {
			return windows.ERROR_INVALID_NAME
		}
	}
	if last := name[len(name)-1]; last == ' ' || last == '.' {
		return windows.ERROR_INVALID_NAME
	}
	if isReservedWindowsDevice(name) {
		return windows.ERROR_INVALID_NAME
	}
	return nil
}

func isReservedWindowsDevice(name string) bool {
	stem, _, _ := strings.Cut(name, ".")
	stem = strings.TrimRight(stem, " ")
	if len(stem) < 3 || len(stem) > 7 {
		return false
	}
	for _, dev := range [...]string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} {
		if strings.EqualFold(stem, dev) {
			return true
		}
	}
	if !strings.EqualFold(stem[:3], "COM") && !strings.EqualFold(stem[:3], "LPT") {
		return false
	}
	r, size := utf8.DecodeRuneInString(stem[3:])
	if size == 0 || size != len(stem)-3 {
		return false
	}
	return (r >= '0' && r <= '9') || r == '\u00b9' || r == '\u00b2' || r == '\u00b3'
}

// ntPathAtOrBelow reports whether path names root or a descendant of root when
// both carry non-empty VOLUME_NAME_NT prefixes (such as \Device\HarddiskVolume3\...).
func ntPathAtOrBelow(path, root string) bool {
	root = strings.TrimRight(root, `\`)
	path = strings.TrimRight(path, `\`)
	if root == "" || path == "" {
		return false
	}
	return foldPrefixBoundary(path, root)
}

func foldPrefixBoundary(path, root string) bool {
	for root != "" {
		if path == "" {
			return false
		}
		pr, pn := utf8.DecodeRuneInString(path)
		rr, rn := utf8.DecodeRuneInString(root)
		if pr != rr && !strings.EqualFold(path[:pn], root[:rn]) {
			return false
		}
		path, root = path[pn:], root[rn:]
	}
	return path == "" || path[0] == '\\'
}
