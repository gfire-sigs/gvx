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
	"fmt"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gverrors "z.gfire.dev/gvx/pkg/errors"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func (e *env) pwriteFlags(fd *vfs.FileDescription, data string, off int64, flags uint32) (int64, error) {
	return fd.PWrite(e.ctx, usermem.BytesIOSequence([]byte(data)), off, vfs.WriteOptions{Flags: flags})
}

func (e *env) writeFlags(fd *vfs.FileDescription, data string, flags uint32) (int64, error) {
	return fd.Write(e.ctx, usermem.BytesIOSequence([]byte(data)), vfs.WriteOptions{Flags: flags})
}

func (e *env) preadFlags(fd *vfs.FileDescription, n int, off int64, flags uint32) ([]byte, error) {
	buf := make([]byte, n)
	got, err := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), off, vfs.ReadOptions{Flags: flags})
	return buf[:got], err
}

func (e *env) position(fd *vfs.FileDescription) int64 {
	e.t.Helper()
	pos, err := fd.Seek(e.ctx, 0, linux.SEEK_CUR)
	if err != nil {
		e.t.Fatalf("lseek(SEEK_CUR): %v", err)
	}
	return pos
}

func TestReadWriteFlagsAcceptTheFlagsOfExt4(t *testing.T) {
	e := newEnv(t)
	fd := e.own(e.fileWith("f", []byte("0123456789")))
	for _, flag := range []uint32{linux.RWF_HIPRI, linux.RWF_DSYNC, linux.RWF_SYNC, rwfNoWait, rwfAppend, rwfNoAppend} {
		t.Run(fmt.Sprintf("flag %#x", flag), func(t *testing.T) {
			got, err := e.preadFlags(fd, 4, 2, flag)
			if err != nil || string(got) != "2345" {
				t.Fatalf("pread with the flag = (%q, %v), want 2345", got, err)
			}
			if n, err := e.pwriteFlags(fd, "ab", 0, flag); err != nil || n != 2 {
				t.Fatalf("pwrite with the flag = (%d, %v), want 2 bytes", n, err)
			}
		})
	}
}

func TestReadWriteFlagsRejectWhatLinuxRejects(t *testing.T) {
	e := newEnv(t)
	fd := e.own(e.fileWith("f", []byte("0123456789")))
	tests := []struct {
		name  string
		flags uint32
		want  *gverrors.Error
	}{
		{"atomic write", 0x40, linuxerr.EOPNOTSUPP},
		{"uncached io", 0x80, linuxerr.EOPNOTSUPP},
		{"unknown high bit", 0x8000, linuxerr.EOPNOTSUPP},
		{"append with noappend", rwfAppend | rwfNoAppend, linuxerr.EINVAL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.preadFlags(fd, 4, 0, tc.flags); !linuxerr.Equals(tc.want, err) {
				t.Errorf("pread = %v, want %v", err, tc.want)
			}
			if _, err := e.pwriteFlags(fd, "x", 0, tc.flags); !linuxerr.Equals(tc.want, err) {
				t.Errorf("pwrite = %v, want %v", err, tc.want)
			}
		})
	}
	wantBytes(t, "content after the rejected calls", e.readAll(fd), []byte("0123456789"))
}

func TestAppendFlagWritesAtTheEndOfTheFile(t *testing.T) {
	e := newEnv(t)
	fd := e.own(e.fileWith("f", []byte("0123456789")))

	// pwritev2 with an offset ignores the offset and leaves the file position.
	if n, err := e.pwriteFlags(fd, "AB", 3, rwfAppend); err != nil || n != 2 {
		t.Fatalf("pwrite with RWF_APPEND = (%d, %v), want 2 bytes", n, err)
	}
	wantBytes(t, "content", e.readAll(fd), []byte("0123456789AB"))
	if pos := e.position(fd); pos != 0 {
		t.Fatalf("file position %d after pwrite with RWF_APPEND, want 0", pos)
	}

	// pwritev2 with offset -1 is write(2) with the flag. It moves the position
	// behind the data.
	if n, err := e.writeFlags(fd, "CD", rwfAppend); err != nil || n != 2 {
		t.Fatalf("write with RWF_APPEND = (%d, %v), want 2 bytes", n, err)
	}
	wantBytes(t, "content", e.readAll(fd), []byte("0123456789ABCD"))
	if pos := e.position(fd); pos != 14 {
		t.Fatalf("file position %d after write with RWF_APPEND, want 14", pos)
	}

	// Without the flag, a positional write stays where it is.
	if n, err := e.pwriteFlags(fd, "xy", 1, 0); err != nil || n != 2 {
		t.Fatalf("pwrite = (%d, %v), want 2 bytes", n, err)
	}
	wantBytes(t, "content", e.readAll(fd), []byte("0xy3456789ABCD"))
}

func TestNoAppendFlagWritesAtTheOffsetOfAnAppendDescription(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("0123456789"))
	fd := e.own(e.mustOpen("f", linux.O_RDWR|linux.O_APPEND))

	// O_APPEND sends a positional write to the end of the file.
	if _, err := e.pwriteFlags(fd, "AB", 2, 0); err != nil {
		t.Fatal(err)
	}
	wantBytes(t, "content after pwrite on O_APPEND", e.readAll(fd), []byte("0123456789AB"))

	// RWF_NOAPPEND removes O_APPEND for the call.
	if _, err := e.pwriteFlags(fd, "xy", 2, rwfNoAppend); err != nil {
		t.Fatal(err)
	}
	wantBytes(t, "content after pwrite with RWF_NOAPPEND", e.readAll(fd), []byte("01xy456789AB"))

	// A write at the file position follows the same rule.
	if _, err := fd.Seek(e.ctx, 4, linux.SEEK_SET); err != nil {
		t.Fatal(err)
	}
	if _, err := e.writeFlags(fd, "zz", rwfNoAppend); err != nil {
		t.Fatal(err)
	}
	wantBytes(t, "content after write with RWF_NOAPPEND", e.readAll(fd), []byte("01xyzz6789AB"))
	if pos := e.position(fd); pos != 6 {
		t.Fatalf("file position %d after write with RWF_NOAPPEND, want 6", pos)
	}
}

func TestNoWaitFlagDoesNotChangeTheResult(t *testing.T) {
	e := newEnv(t)
	fd := e.own(e.fileWith("f", pattern(1, 3*blockSize)))
	got, err := e.preadFlags(fd, blockSize, blockSize, rwfNoWait)
	if err != nil {
		t.Fatalf("pread with RWF_NOWAIT: %v", err)
	}
	wantBytes(t, "pread with RWF_NOWAIT", got, pattern(1, 3*blockSize)[blockSize:2*blockSize])
	data := pattern(2, blockSize)
	if n, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(data), 3*blockSize, vfs.WriteOptions{Flags: rwfNoWait}); err != nil || n != blockSize {
		t.Fatalf("pwrite with RWF_NOWAIT = (%d, %v), want %d bytes", n, err, blockSize)
	}
	wantBytes(t, "file after pwrite with RWF_NOWAIT", e.readAll(fd), append(pattern(1, 3*blockSize), data...))
}
