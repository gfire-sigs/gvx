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

//go:build !windows

package hostfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// direntBufferSize is the buffer size of one getdents call. A larger buffer
// holds more entries per call, which matters on macOS: its emulation of
// getdirentries rescans the directory from the start for each call.
const direntBufferSize = 64 * 1024

var direntBuffers = sync.Pool{New: func() any {
	b := make([]byte, direntBufferSize)
	return &b
}}

// Field offsets of the directory entry record. The record layout differs
// between Linux and macOS, but both name the same four fields.
const (
	direntInoOffset    = unsafe.Offsetof(unix.Dirent{}.Ino)
	direntReclenOffset = unsafe.Offsetof(unix.Dirent{}.Reclen)
	direntTypeOffset   = unsafe.Offsetof(unix.Dirent{}.Type)
	direntNameOffset   = unsafe.Offsetof(unix.Dirent{}.Name)
)

var errMalformedDirent = errors.New("hostfs: malformed directory entry record")

// reopenDir opens the directory that dir names again, with a file description
// of its own. A listing needs it, because every getdents call moves the offset
// of the description.
func reopenDir(dir hostDirHandle) (*os.File, error) {
	fd, err := openatRetry(int(dir), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("hostfs: reopen directory: %w", err)
	}
	return os.NewFile(uintptr(fd), "."), nil
}

func (h *hostRoot) readDir(rel string) ([]hostDirEntry, error) {
	dir, err := h.openDir(rel)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = dir.Close()
	}()
	return readDirFile(dir, rel)
}

func (h *hostRoot) readDirAt(dir hostDirHandle) ([]hostDirEntry, error) {
	f, err := reopenDir(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	return readDirFile(f, ".")
}

// readDirFile lists the open directory f. It takes the type and the inode
// number of each entry from the directory record, so a listing costs no call
// for each entry. A file system that leaves the type unknown costs one
// lstat for that entry. The path rel only labels errors.
func readDirFile(f *os.File, rel string) ([]hostDirEntry, error) {
	bufp := direntBuffers.Get().(*[]byte)
	defer direntBuffers.Put(bufp)
	buf := *bufp
	var out []hostDirEntry
	err := withFileFD(f, func(fd int) error {
		for {
			var n int
			if err := retryEINTR(func() error {
				var rerr error
				n, rerr = unix.ReadDirent(fd, buf)
				return rerr
			}); err != nil {
				return err
			}
			if n <= 0 {
				return nil
			}
			var perr error
			if out, perr = parseDirents(fd, buf[:n], out); perr != nil {
				return perr
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("hostfs: read directory %q: %w", rel, err)
	}
	return out, nil
}

// parseDirents appends the entries of one getdents buffer to out. It skips "."
// and "..". dirfd resolves the entries of an unknown type.
func parseDirents(dirfd int, buf []byte, out []hostDirEntry) ([]hostDirEntry, error) {
	for len(buf) > 0 {
		if len(buf) < int(direntNameOffset) {
			return out, errMalformedDirent
		}
		reclen := int(binary.NativeEndian.Uint16(buf[direntReclenOffset:]))
		if reclen < int(direntNameOffset) || reclen > len(buf) {
			return out, errMalformedDirent
		}
		rec := buf[:reclen]
		buf = buf[reclen:]
		ino := binary.NativeEndian.Uint64(rec[direntInoOffset:])
		if ino == 0 {
			// A removed entry that the directory block still holds.
			continue
		}
		nameBytes := rec[direntNameOffset:]
		if i := bytes.IndexByte(nameBytes, 0); i >= 0 {
			nameBytes = nameBytes[:i]
		}
		name := string(nameBytes)
		if name == "" || name == "." || name == ".." {
			continue
		}
		kind, ok := direntKind(rec[direntTypeOffset])
		if !ok {
			var st unix.Stat_t
			serr := retryEINTR(func() error { return unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) })
			if errors.Is(serr, unix.ENOENT) {
				// The entry vanished after the listing: a concurrent unlink.
				continue
			}
			if serr != nil {
				return out, fmt.Errorf("hostfs: lstat %q: %w", name, serr)
			}
			info := statToHostInfo(&st)
			out = append(out, hostDirEntry{name: name, kind: info.kind, ino: info.id.ino})
			continue
		}
		out = append(out, hostDirEntry{name: name, kind: kind, ino: ino})
	}
	return out, nil
}

// direntKind maps the d_type field of a directory record. It reports false for
// DT_UNKNOWN, where only a stat gives the type.
func direntKind(t uint8) (hostKind, bool) {
	switch t {
	case unix.DT_REG:
		return hostKindRegular, true
	case unix.DT_DIR:
		return hostKindDir, true
	case unix.DT_LNK:
		return hostKindSymlink, true
	case unix.DT_UNKNOWN:
		return 0, false
	}
	return hostKindOther, true
}

func (h *hostRoot) syncDirAt(dir hostDirHandle) error {
	f, err := reopenDir(dir)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil {
		return fmt.Errorf("hostfs: sync directory: %w", syncErr)
	}
	return closeErr
}
