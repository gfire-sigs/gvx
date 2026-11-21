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

package darwinacl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

var (
	errInvalidACL  = errors.New("invalid Darwin ACL")
	errUnsafeGrant = errors.New("unsafe Darwin ACL grant")
)

// Validate permits no ACL grants on private paths and only read grants otherwise.
func Validate(fd int, private bool) error {
	// The extended attribute references kauth_filesec data. Its ACL grants
	// can exceed the mode bits reported by stat.
	const (
		filesecMagic       = 0x012cc16d
		filesecHeader      = 44
		entrySize          = 24
		maxEntries         = 128
		noACL              = uint32(0xffffffff)
		kindMask           = 0xf
		permit             = 1
		deny               = 2
		inheritOnly        = 1 << 8
		ancestorReadRights = 1<<1 | 1<<3 | 1<<7 | 1<<9 | 1<<11 | 1<<20 | 1<<22 | 1<<24
	)
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	var buf [12 + filesecHeader + maxEntries*entrySize]byte
	_, _, errno := syscall.Syscall6(unix.SYS_FGETATTRLIST, uintptr(fd), uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("read Darwin ACL: %w", errno)
	}
	end := int(binary.NativeEndian.Uint32(buf[:4]))
	if end < 12 || end > len(buf) {
		return errInvalidACL
	}
	length := int(binary.NativeEndian.Uint32(buf[8:12]))
	if length == 0 {
		return nil
	}
	start := 4 + int(int32(binary.NativeEndian.Uint32(buf[4:8])))
	if start < 12 || length < filesecHeader || start+length > end {
		return errInvalidACL
	}
	acl := buf[start : start+length]
	count := binary.NativeEndian.Uint32(acl[36:40])
	if count == noACL {
		count = 0
	}
	if binary.NativeEndian.Uint32(acl[:4]) != filesecMagic || count > maxEntries || len(acl) != filesecHeader+int(count)*entrySize {
		return errInvalidACL
	}
	for entry := filesecHeader; entry < len(acl); entry += entrySize {
		flags := binary.NativeEndian.Uint32(acl[entry+16:])
		rights := binary.NativeEndian.Uint32(acl[entry+20:])
		if flags&inheritOnly != 0 || flags&kindMask == deny {
			continue
		}
		if flags&kindMask != permit || private || rights&^ancestorReadRights != 0 {
			return errUnsafeGrant
		}
	}
	return nil
}
