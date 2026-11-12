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

package erofs

import (
	"encoding/binary"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/log"
)

// Sizes and flags of the on-disk xattr structures.
//
// An inode's inline xattr area starts with a 12-byte header, followed by
// SharedCount 4-byte ids into the shared xattr area, followed by entries.
// Each entry has a 4-byte header, the name suffix, and the value, padded to
// four bytes. Refer: https://docs.kernel.org/filesystems/erofs.html#extended-attributes
const (
	XattrIbodyHeaderSize = 12
	XattrEntryHeaderSize = 4
	XattrAlign           = 4

	// XattrLongPrefixFlag marks a name index that refers to the long prefix
	// table. This implementation does not support long prefixes.
	XattrLongPrefixFlag = 0x80

	// MaxXattrIbodySize is the largest inline xattr area that the 16-bit
	// i_xattr_icount field can encode. The header counts as one 4-byte unit.
	MaxXattrIbodySize = XattrIbodyHeaderSize + XattrAlign*(1<<16-2)
)

// Name indexes of the predefined xattr name prefixes.
const (
	XattrIndexUser            = 1
	XattrIndexPosixACLAccess  = 2
	XattrIndexPosixACLDefault = 3
	XattrIndexTrusted         = 4
	XattrIndexLustre          = 5
	XattrIndexSecurity        = 6
)

// XattrPrefixes maps predefined name indexes to the name prefix that the
// entry's stored name suffix extends.
var XattrPrefixes = map[uint8]string{
	XattrIndexUser:            linux.XATTR_USER_PREFIX,
	XattrIndexPosixACLAccess:  linux.XATTR_NAME_POSIX_ACL_ACCESS,
	XattrIndexPosixACLDefault: linux.XATTR_NAME_POSIX_ACL_DEFAULT,
	XattrIndexTrusted:         linux.XATTR_TRUSTED_PREFIX,
	XattrIndexSecurity:        linux.XATTR_SECURITY_PREFIX,
}

// xattrIbodySize returns the size in bytes of the inline xattr area for an
// inode with the given i_xattr_icount. The header counts as one 4-byte unit
// even though it occupies 12 bytes, as in Linux's erofs_xattr_ibody_size().
func xattrIbodySize(icount uint16) uint32 {
	if icount == 0 {
		return 0
	}
	return XattrIbodyHeaderSize + XattrAlign*(uint32(icount)-1)
}

// XattrIcount returns the i_xattr_icount value that encodes an inline xattr
// area of ibodySize bytes. ibodySize must be zero or at least the header size
// plus a multiple of XattrAlign.
func XattrIcount(ibodySize uint32) uint16 {
	if ibodySize == 0 {
		return 0
	}
	return uint16((ibodySize-XattrIbodyHeaderSize)/XattrAlign + 1)
}

// XattrEntrySize returns the aligned on-disk size of an xattr entry.
func XattrEntrySize(nameLen, valueLen int) int {
	return (XattrEntryHeaderSize + nameLen + valueLen + XattrAlign - 1) &^ (XattrAlign - 1)
}

// Rdev returns the device numbers of a character or block device inode.
// Other inode types report 0:0.
func (i *Inode) Rdev() (major, minor uint32) {
	if !i.IsCharDev() && !i.IsBlockDev() {
		return 0, 0
	}
	maj, min := linux.DecodeDeviceID(i.rdev)
	return uint32(maj), min
}

// ListXattrs returns the full names of all xattrs of this inode. Entries whose
// name index is not predefined are skipped, as Linux does when listing.
func (i *Inode) ListXattrs() ([]string, error) {
	var names []string
	err := i.iterXattrs(func(name string, _ []byte) bool {
		names = append(names, name)
		return false
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

// GetXattr returns the value of the xattr with the given full name. It returns
// linuxerr.ENODATA if the inode has no such xattr.
func (i *Inode) GetXattr(name string) ([]byte, error) {
	var value []byte
	found := false
	err := i.iterXattrs(func(n string, v []byte) bool {
		if n != name {
			return false
		}
		value = append([]byte(nil), v...)
		found = true
		return true
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, linuxerr.ENODATA
	}
	return value, nil
}

// iterXattrs calls cb for every xattr until cb returns true. The value slice
// aliases the image mapping and is valid only during the callback.
func (i *Inode) iterXattrs(cb func(name string, value []byte) bool) error {
	if i.xattrIsize == 0 {
		return nil
	}
	corrupt := func() error {
		log.Warningf("Corrupted xattr area at inode (nid=%v)", i.Nid())
		return linuxerr.EUCLEAN
	}
	if i.xattrIsize < XattrIbodyHeaderSize {
		return corrupt()
	}
	ibody, err := i.image.BytesAt(i.xattrOff, uint64(i.xattrIsize))
	if err != nil {
		return corrupt()
	}

	sharedCount := uint32(ibody[4])
	pos := uint32(XattrIbodyHeaderSize)
	if pos+sharedCount*XattrAlign > i.xattrIsize {
		return corrupt()
	}
	for n := uint32(0); n < sharedCount; n++ {
		id := binary.LittleEndian.Uint32(ibody[pos+n*XattrAlign:])
		off := i.image.sb.BlockAddrToOffset(i.image.sb.XattrBlockAddr) + uint64(id)*XattrAlign
		entry, _, err := i.image.xattrEntryAt(off, 0)
		if err != nil {
			return corrupt()
		}
		if name, ok := entry.fullName(); ok && cb(name, entry.value) {
			return nil
		}
	}
	pos += sharedCount * XattrAlign

	for pos < i.xattrIsize {
		entry, size, err := parseXattrEntry(ibody[pos:])
		if err != nil {
			return corrupt()
		}
		pos += size
		if entry.index&XattrLongPrefixFlag != 0 {
			return linuxerr.ENOTSUP
		}
		if name, ok := entry.fullName(); ok && cb(name, entry.value) {
			return nil
		}
	}
	return nil
}

type xattrEntry struct {
	index uint8
	name  []byte
	value []byte
}

// fullName returns the complete xattr name. ok is false for name indexes this
// implementation does not know.
func (e *xattrEntry) fullName() (string, bool) {
	if e.index == 0 {
		return string(e.name), true
	}
	prefix, ok := XattrPrefixes[e.index]
	if !ok {
		return "", false
	}
	return prefix + string(e.name), true
}

// parseXattrEntry decodes the entry at the start of b. It returns the entry
// and its aligned size.
func parseXattrEntry(b []byte) (xattrEntry, uint32, error) {
	if len(b) < XattrEntryHeaderSize {
		return xattrEntry{}, 0, linuxerr.EUCLEAN
	}
	nameLen := int(b[0])
	valueLen := int(binary.LittleEndian.Uint16(b[2:4]))
	end := XattrEntryHeaderSize + nameLen + valueLen
	if end > len(b) {
		return xattrEntry{}, 0, linuxerr.EUCLEAN
	}
	return xattrEntry{
		index: b[1],
		name:  b[XattrEntryHeaderSize : XattrEntryHeaderSize+nameLen],
		value: b[XattrEntryHeaderSize+nameLen : end],
	}, uint32(XattrEntrySize(nameLen, valueLen)), nil
}

// xattrEntryAt decodes the xattr entry stored at image offset off. A nonzero
// bound limits how many bytes after off the entry may span.
func (i *Image) xattrEntryAt(off, bound uint64) (xattrEntry, uint32, error) {
	hdr, err := i.BytesAt(off, XattrEntryHeaderSize)
	if err != nil {
		return xattrEntry{}, 0, err
	}
	total := uint64(XattrEntryHeaderSize) + uint64(hdr[0]) + uint64(binary.LittleEndian.Uint16(hdr[2:4]))
	if bound != 0 && total > bound {
		return xattrEntry{}, 0, linuxerr.EUCLEAN
	}
	b, err := i.BytesAt(off, total)
	if err != nil {
		return xattrEntry{}, 0, err
	}
	return parseXattrEntry(b)
}
