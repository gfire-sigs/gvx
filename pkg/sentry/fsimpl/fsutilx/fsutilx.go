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

// Package fsutilx provides shared VFS2 helpers for extended attributes,
// statx and SetStat validation, fallocate mode and range checks, seek offset
// calculation, and read-write flag validation across hostfs and ext4lite.
package fsutilx

import (
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// BasicStatxMask is the statx attribute mask returned by hostfs and ext4lite.
const BasicStatxMask = uint32(linux.STATX_BASIC_STATS | linux.STATX_BTIME)

// SupportedSetStatMask lists the statx fields accepted by SetStat.
const SupportedSetStatMask = uint32(
	linux.STATX_MODE |
		linux.STATX_UID |
		linux.STATX_GID |
		linux.STATX_ATIME |
		linux.STATX_MTIME |
		linux.STATX_CTIME |
		linux.STATX_SIZE,
)

// Per-call preadv2 and pwritev2 flags beyond pkg/abi/linux.
const (
	RWFNoWait        = uint32(0x8)
	RWFAppend        = uint32(0x10)
	RWFNoAppend      = uint32(0x20)
	SupportedRWFlags = uint32(linux.RWF_HIPRI | linux.RWF_DSYNC | linux.RWF_SYNC | RWFNoWait | RWFAppend | RWFNoAppend)
)

// Fallocate mode masks for hostfs and ext4lite.
const (
	HostfsFallocateModes = uint64(linux.FALLOC_FL_KEEP_SIZE | linux.FALLOC_FL_PUNCH_HOLE)
	Ext4FallocateModes   = uint64(
		linux.FALLOC_FL_KEEP_SIZE |
			linux.FALLOC_FL_PUNCH_HOLE |
			linux.FALLOC_FL_ZERO_RANGE |
			linux.FALLOC_FL_COLLAPSE_RANGE |
			linux.FALLOC_FL_INSERT_RANGE,
	)
)

// FallocateOp identifies the operation selected by fallocate mode flags.
type FallocateOp uint8

const (
	// FallocateReserve allocates or reserves space over the byte range.
	FallocateReserve FallocateOp = iota
	// FallocatePunchHole deallocates and zeroes the byte range while keeping size.
	FallocatePunchHole
	// FallocateZeroRange zeroes the byte range and extends size unless keep-size is set.
	FallocateZeroRange
	// FallocateCollapseRange removes the byte range and shifts trailing extents down.
	FallocateCollapseRange
	// FallocateInsertRange inserts a zeroed hole and shifts trailing extents up.
	FallocateInsertRange
)

var xattrPrefixes = []string{
	linux.XATTR_USER_PREFIX,
	linux.XATTR_TRUSTED_PREFIX,
	linux.XATTR_SECURITY_PREFIX,
}

// CheckXattrPrefix accepts the user, trusted, and security extended attribute
// namespaces and rejects all other prefixes with EOPNOTSUPP.
func CheckXattrPrefix(name string) error {
	for _, prefix := range xattrPrefixes {
		if strings.HasPrefix(name, prefix) {
			return nil
		}
	}
	return linuxerr.EOPNOTSUPP
}

// CheckXattrName validates the length and namespace prefix of name.
func CheckXattrName(name string) error {
	if len(name) > linux.XATTR_NAME_MAX {
		return linuxerr.ERANGE
	}
	return CheckXattrPrefix(name)
}

// CheckSetXattrFlags validates setxattr flags against whether the attribute
// already exists on the target inode.
func CheckSetXattrFlags(flags uint32, exists bool) error {
	if flags&^uint32(linux.XATTR_CREATE|linux.XATTR_REPLACE) != 0 {
		return linuxerr.EINVAL
	}
	if flags&linux.XATTR_CREATE != 0 && exists {
		return linuxerr.EEXIST
	}
	if flags&linux.XATTR_REPLACE != 0 && !exists {
		return linuxerr.ENODATA
	}
	return nil
}

// XattrMapBytes returns the total byte size of all names and values in m.
func XattrMapBytes(m map[string][]byte) int {
	total := 0
	for name, value := range m {
		total += len(name) + len(value)
	}
	return total
}

// SetXattrMap returns a copy of cur with name set to value after enforcing
// XATTR_SIZE_MAX, XATTR_CREATE, XATTR_REPLACE, and maxBytes.
func SetXattrMap(cur map[string][]byte, name string, value []byte, flags uint32, maxBytes int) (map[string][]byte, error) {
	if len(value) > linux.XATTR_SIZE_MAX {
		return nil, linuxerr.E2BIG
	}
	_, exists := cur[name]
	if flags&linux.XATTR_CREATE != 0 && exists {
		return nil, linuxerr.EEXIST
	}
	if flags&linux.XATTR_REPLACE != 0 && !exists {
		return nil, linuxerr.ENODATA
	}
	next := make(map[string][]byte, len(cur)+1)
	maps.Copy(next, cur)
	next[name] = slices.Clone(value)
	if maxBytes > 0 && XattrMapBytes(next) > maxBytes {
		return nil, linuxerr.ENOSPC
	}
	return next, nil
}

// RemoveXattrMap returns a copy of cur without name, or ENODATA when name is
// absent. An empty result returns nil.
func RemoveXattrMap(cur map[string][]byte, name string) (map[string][]byte, error) {
	if _, ok := cur[name]; !ok {
		return nil, linuxerr.ENODATA
	}
	if len(cur) == 1 {
		return nil, nil
	}
	next := maps.Clone(cur)
	delete(next, name)
	return next, nil
}

// FilterXattrList filters extended attribute names for a caller with creds and
// validates that the NUL-terminated list fits within size when size is non-zero.
func FilterXattrList(all []string, creds *auth.Credentials, size uint64) ([]string, error) {
	haveCap := creds.HasRootCapability(linux.CAP_SYS_ADMIN)
	names := make([]string, 0, len(all))
	listSize := 0
	for _, name := range all {
		if CheckXattrPrefix(name) != nil {
			continue
		}
		if !haveCap && strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
			continue
		}
		names = append(names, name)
		listSize += len(name) + 1
	}
	if size != 0 && uint64(listSize) > size {
		return nil, linuxerr.ERANGE
	}
	return names, nil
}

// CheckGetXattr validates file read permissions, attribute prefix, and xattr
// read permissions for getxattr.
func CheckGetXattr(creds *auth.Credentials, mode linux.FileMode, uid auth.KUID, gid auth.KGID, name string) error {
	if vfs.XattrReadNeedsFilePermission(name) {
		if err := vfs.GenericCheckPermissions(creds, vfs.MayRead, mode, nil, uid, gid); err != nil {
			return err
		}
	}
	if err := CheckXattrPrefix(name); err != nil {
		return err
	}
	return vfs.CheckXattrPermissions(creds, vfs.MayRead, mode, uid, name)
}

// FinishGetXattr validates the caller buffer size and applies
// security.capability fixups to a raw extended attribute value.
func FinishGetXattr(creds *auth.Credentials, opts *vfs.GetXattrOptions, raw []byte) (string, error) {
	value := string(raw)
	if opts.Size != 0 && uint64(len(value)) > opts.Size {
		return "", linuxerr.ERANGE
	}
	if opts.Name == linux.XATTR_SECURITY_CAPABILITY {
		return auth.FixupVfsCapDataOnGet(creds, value)
	}
	return value, nil
}

// CheckSetXattr validates the attribute prefix, file write permissions, and
// xattr write permissions for setxattr and removexattr.
func CheckSetXattr(creds *auth.Credentials, mode linux.FileMode, uid auth.KUID, gid auth.KGID, name string) error {
	if err := CheckXattrPrefix(name); err != nil {
		return err
	}
	if err := vfs.GenericCheckPermissions(creds, vfs.MayWrite, mode, nil, uid, gid); err != nil {
		return err
	}
	return vfs.CheckXattrPermissions(creds, vfs.MayWrite, mode, uid, name)
}

// PrepareSetXattrValue applies security.capability fixups for setxattr.
func PrepareSetXattrValue(creds *auth.Credentials, uid auth.KUID, gid auth.KGID, opts *vfs.SetXattrOptions) (string, error) {
	if opts.Name == linux.XATTR_SECURITY_CAPABILITY {
		return auth.FixupVfsCapDataOnSet(creds, opts.Value, uid, gid)
	}
	return opts.Value, nil
}

// CheckRemoveXattr validates the attribute prefix, file write permissions, and
// xattr write permissions for removexattr.
func CheckRemoveXattr(creds *auth.Credentials, mode linux.FileMode, uid auth.KUID, gid auth.KGID, name string) error {
	return CheckSetXattr(creds, mode, uid, gid, name)
}

// StatxAttr holds the inode attributes used to populate a linux.Statx record.
type StatxAttr struct {
	Blksize   uint32
	Nlink     uint32
	UID       uint32
	GID       uint32
	Mode      uint16
	Ino       uint64
	Size      uint64
	Blocks    uint64
	Atime     linux.StatxTimestamp
	Mtime     linux.StatxTimestamp
	Ctime     linux.StatxTimestamp
	Btime     linux.StatxTimestamp
	DevMajor  uint32
	DevMinor  uint32
	RdevMajor uint32
	RdevMinor uint32
}

// NewStatx builds a linux.Statx record with BasicStatxMask.
func NewStatx(a StatxAttr) linux.Statx {
	return linux.Statx{
		Mask:      BasicStatxMask,
		Blksize:   a.Blksize,
		Nlink:     a.Nlink,
		UID:       a.UID,
		GID:       a.GID,
		Mode:      a.Mode,
		Ino:       a.Ino,
		Size:      a.Size,
		Blocks:    a.Blocks,
		Atime:     a.Atime,
		Mtime:     a.Mtime,
		Ctime:     a.Ctime,
		Btime:     a.Btime,
		DevMajor:  a.DevMajor,
		DevMinor:  a.DevMinor,
		RdevMajor: a.RdevMajor,
		RdevMinor: a.RdevMinor,
	}
}

// StatxTimestampFromTime converts a time.Time to a linux.StatxTimestamp.
func StatxTimestampFromTime(t time.Time) linux.StatxTimestamp {
	return linux.StatxTimestamp{Sec: t.Unix(), Nsec: uint32(t.Nanosecond())}
}

// ResolveStatxTime resolves a statx timestamp to a time.Time, substituting now
// when ts.Nsec equals UTIME_NOW.
func ResolveStatxTime(ts linux.StatxTimestamp, now time.Time) time.Time {
	if ts.Nsec == linux.UTIME_NOW {
		return now
	}
	return time.Unix(ts.Sec, int64(ts.Nsec))
}

// ResolveStatxTimestamp resolves a statx timestamp, substituting now when
// ts.Nsec equals UTIME_NOW.
func ResolveStatxTimestamp(ts, now linux.StatxTimestamp) linux.StatxTimestamp {
	if ts.Nsec == linux.UTIME_NOW {
		return now
	}
	return ts
}

// CheckSetStat validates the SetStat mask and caller permissions.
func CheckSetStat(ctx context.Context, creds *auth.Credentials, opts *vfs.SetStatOptions, mode linux.FileMode, uid auth.KUID, gid auth.KGID) error {
	if opts.Stat.Mask&^SupportedSetStatMask != 0 {
		return linuxerr.EPERM
	}
	return vfs.CheckSetStat(ctx, creds, opts, mode, nil, uid, gid)
}

// CheckTruncateFileType validates that mode names a regular file for STATX_SIZE.
func CheckTruncateFileType(mode uint32) error {
	switch mode & linux.S_IFMT {
	case linux.S_IFDIR:
		return linuxerr.EISDIR
	case linux.S_IFREG:
		return nil
	default:
		return linuxerr.EINVAL
	}
}

// ClearSUIDAndSGID clears the set-user-ID and set-group-ID bits of a
// non-directory mode while preserving the file type bits.
func ClearSUIDAndSGID(mode uint32) uint32 {
	if mode&linux.S_IFMT == linux.S_IFDIR {
		return mode
	}
	return vfs.ClearSUIDAndSGID(mode&^uint32(linux.S_IFMT)) | (mode & linux.S_IFMT)
}

// ClearPrivsMode returns mode without set-user-ID and set-group-ID bits unless
// creds holds CAP_FSETID for the file.
func ClearPrivsMode(creds *auth.Credentials, mode uint32, uid, gid uint32) uint32 {
	if creds != nil && creds.HasCapabilityOnFile(linux.CAP_FSETID, auth.KUID(uid), auth.KGID(gid)) {
		return mode
	}
	return ClearSUIDAndSGID(mode)
}

// ParseFallocateMode validates fallocate mode bits against the supported mask
// and returns the operation and whether FALLOC_FL_KEEP_SIZE is set.
func ParseFallocateMode(mode, supported uint64) (FallocateOp, bool, error) {
	if mode&^supported != 0 {
		return 0, false, linuxerr.EOPNOTSUPP
	}
	keepSize := mode&linux.FALLOC_FL_KEEP_SIZE != 0
	switch mode &^ linux.FALLOC_FL_KEEP_SIZE {
	case 0:
		return FallocateReserve, keepSize, nil
	case linux.FALLOC_FL_PUNCH_HOLE:
		if !keepSize {
			return 0, false, linuxerr.EOPNOTSUPP
		}
		return FallocatePunchHole, true, nil
	case linux.FALLOC_FL_ZERO_RANGE:
		return FallocateZeroRange, keepSize, nil
	case linux.FALLOC_FL_COLLAPSE_RANGE:
		if keepSize {
			return 0, false, linuxerr.EOPNOTSUPP
		}
		return FallocateCollapseRange, false, nil
	case linux.FALLOC_FL_INSERT_RANGE:
		if keepSize {
			return 0, false, linuxerr.EOPNOTSUPP
		}
		return FallocateInsertRange, false, nil
	default:
		return 0, false, linuxerr.EOPNOTSUPP
	}
}

// CheckFallocateRange validates that offset and length are positive 63-bit
// bounds whose sum does not overflow or exceed maxEnd.
func CheckFallocateRange(offset, length, maxEnd uint64) (uint64, error) {
	if length == 0 || offset > math.MaxInt64 || length > math.MaxInt64 {
		return 0, linuxerr.EINVAL
	}
	end := offset + length
	if end < offset || end > maxEnd {
		return 0, linuxerr.EFBIG
	}
	return end, nil
}

// CheckFallocateLimit enforces RLIMIT_FSIZE on size-extending fallocate calls.
func CheckFallocateLimit(ctx context.Context, offset, length uint64, checkLimit bool) error {
	if !checkLimit || limits.FromContext(ctx) == nil {
		return nil
	}
	limit, err := vfs.CheckLimit(ctx, int64(offset), int64(length))
	if err != nil {
		return err
	}
	if limit < int64(length) {
		return linuxerr.ErrExceedsFileSizeLimit
	}
	return nil
}

// SeekBasic computes the new offset for SEEK_SET, SEEK_CUR, and SEEK_END.
func SeekBasic(cur, offset int64, whence int32, sizeFn func() (int64, error)) (int64, error) {
	var newOff int64
	switch whence {
	case linux.SEEK_SET:
		newOff = offset
	case linux.SEEK_CUR:
		newOff = cur + offset
	case linux.SEEK_END:
		size, err := sizeFn()
		if err != nil {
			return 0, err
		}
		newOff = size + offset
	default:
		return 0, linuxerr.EINVAL
	}
	if newOff < 0 {
		return 0, linuxerr.EINVAL
	}
	return newOff, nil
}

// SeekOffset computes the new offset for SEEK_SET, SEEK_CUR, SEEK_END,
// SEEK_DATA, and SEEK_HOLE. When dataHoleFn is nil, the file is treated as a
// single data range from 0 to size with a virtual hole at size.
func SeekOffset(cur, offset int64, whence int32, sizeFn func() (int64, error), dataHoleFn func(offset int64, seekData bool) (int64, error)) (int64, error) {
	switch whence {
	case linux.SEEK_SET, linux.SEEK_CUR, linux.SEEK_END:
		return SeekBasic(cur, offset, whence, sizeFn)
	case linux.SEEK_DATA, linux.SEEK_HOLE:
		if dataHoleFn != nil {
			newOff, err := dataHoleFn(offset, whence == linux.SEEK_DATA)
			if err != nil {
				return 0, err
			}
			if newOff < 0 {
				return 0, linuxerr.EINVAL
			}
			return newOff, nil
		}
		size, err := sizeFn()
		if err != nil {
			return 0, err
		}
		if offset < 0 || offset >= size {
			return 0, linuxerr.ENXIO
		}
		if whence == linux.SEEK_DATA {
			return offset, nil
		}
		return size, nil
	default:
		return 0, linuxerr.EINVAL
	}
}

// SeekRegular computes the new file offset for a regular file that treats the
// whole file as one data range.
func SeekRegular(cur, offset int64, whence int32, sizeFn func() (int64, error)) (int64, error) {
	return SeekOffset(cur, offset, whence, sizeFn, nil)
}

// CheckRWFlags validates preadv2 and pwritev2 flags against SupportedRWFlags.
func CheckRWFlags(flags uint32) error {
	if flags&^SupportedRWFlags != 0 {
		return linuxerr.EOPNOTSUPP
	}
	if flags&RWFAppend != 0 && flags&RWFNoAppend != 0 {
		return linuxerr.EINVAL
	}
	return nil
}

// AppendsWrite reports whether a write appends to the end of the file.
func AppendsWrite(statusFlags, rwf uint32) bool {
	if rwf&RWFAppend != 0 {
		return true
	}
	return statusFlags&linux.O_APPEND != 0 && rwf&RWFNoAppend == 0
}
