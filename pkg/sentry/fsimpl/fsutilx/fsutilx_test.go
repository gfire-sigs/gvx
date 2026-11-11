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

package fsutilx

import (
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func TestCheckXattrPrefixAndName(t *testing.T) {
	t.Parallel()
	valid := []string{
		"user.key",
		"trusted.key",
		"security.capability",
	}
	for _, name := range valid {
		if err := CheckXattrPrefix(name); err != nil {
			t.Fatalf("CheckXattrPrefix(%q) = %v, want nil", name, err)
		}
		if err := CheckXattrName(name); err != nil {
			t.Fatalf("CheckXattrName(%q) = %v, want nil", name, err)
		}
	}

	invalidPrefix := []string{
		"",
		"system.posix_acl_access",
		"custom.key",
		"user",
	}
	for _, name := range invalidPrefix {
		if err := CheckXattrPrefix(name); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
			t.Fatalf("CheckXattrPrefix(%q) = %v, want EOPNOTSUPP", name, err)
		}
		if err := CheckXattrName(name); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
			t.Fatalf("CheckXattrName(%q) = %v, want EOPNOTSUPP", name, err)
		}
	}

	tooLong := "user." + strings.Repeat("a", linux.XATTR_NAME_MAX)
	if err := CheckXattrName(tooLong); !linuxerr.Equals(linuxerr.ERANGE, err) {
		t.Fatalf("CheckXattrName(len=%d) = %v, want ERANGE", len(tooLong), err)
	}
}

func TestCheckSetXattrFlagsAndMapHelpers(t *testing.T) {
	t.Parallel()
	if err := CheckSetXattrFlags(0, false); err != nil {
		t.Fatalf("flags=0 absent: %v", err)
	}
	if err := CheckSetXattrFlags(0, true); err != nil {
		t.Fatalf("flags=0 present: %v", err)
	}
	if err := CheckSetXattrFlags(linux.XATTR_CREATE, false); err != nil {
		t.Fatalf("XATTR_CREATE absent: %v", err)
	}
	if err := CheckSetXattrFlags(linux.XATTR_CREATE, true); !linuxerr.Equals(linuxerr.EEXIST, err) {
		t.Fatalf("XATTR_CREATE present = %v, want EEXIST", err)
	}
	if err := CheckSetXattrFlags(linux.XATTR_REPLACE, true); err != nil {
		t.Fatalf("XATTR_REPLACE present: %v", err)
	}
	if err := CheckSetXattrFlags(linux.XATTR_REPLACE, false); !linuxerr.Equals(linuxerr.ENODATA, err) {
		t.Fatalf("XATTR_REPLACE absent = %v, want ENODATA", err)
	}
	if err := CheckSetXattrFlags(0x80, false); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("unknown flag = %v, want EINVAL", err)
	}

	m, err := SetXattrMap(nil, "user.k", []byte("val"), linux.XATTR_CREATE, 64)
	if err != nil || string(m["user.k"]) != "val" {
		t.Fatalf("SetXattrMap create = (%v, %v)", m, err)
	}
	if _, err := SetXattrMap(m, "user.k", []byte("v2"), linux.XATTR_CREATE, 64); !linuxerr.Equals(linuxerr.EEXIST, err) {
		t.Fatalf("SetXattrMap duplicate create = %v, want EEXIST", err)
	}
	if _, err := SetXattrMap(m, "user.absent", []byte("v2"), linux.XATTR_REPLACE, 64); !linuxerr.Equals(linuxerr.ENODATA, err) {
		t.Fatalf("SetXattrMap missing replace = %v, want ENODATA", err)
	}
	if _, err := SetXattrMap(m, "user.big", make([]byte, 64), 0, 32); !linuxerr.Equals(linuxerr.ENOSPC, err) {
		t.Fatalf("SetXattrMap over maxBytes = %v, want ENOSPC", err)
	}
	rem, err := RemoveXattrMap(m, "user.k")
	if err != nil || rem != nil {
		t.Fatalf("RemoveXattrMap last = (%v, %v), want (nil, nil)", rem, err)
	}
	if _, err := RemoveXattrMap(rem, "user.k"); !linuxerr.Equals(linuxerr.ENODATA, err) {
		t.Fatalf("RemoveXattrMap absent = %v, want ENODATA", err)
	}
}

func TestFilterXattrList(t *testing.T) {
	t.Parallel()
	rootCreds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	userCreds := auth.NewUserCredentials(1000, 1000, nil, nil, auth.NewRootUserNamespace())

	names := []string{"user.zeta", "trusted.secret", "security.selinux", "system.data", "user.alpha"}
	gotRoot, err := FilterXattrList(names, rootCreds, 0)
	if err != nil {
		t.Fatalf("FilterXattrList root: %v", err)
	}
	wantRoot := []string{"user.zeta", "trusted.secret", "security.selinux", "user.alpha"}
	if !slices.Equal(gotRoot, wantRoot) {
		t.Fatalf("root list = %v, want %v", gotRoot, wantRoot)
	}

	gotUser, err := FilterXattrList(names, userCreds, 0)
	if err != nil {
		t.Fatalf("FilterXattrList user: %v", err)
	}
	wantUser := []string{"user.zeta", "security.selinux", "user.alpha"}
	if !slices.Equal(gotUser, wantUser) {
		t.Fatalf("user list = %v, want %v", gotUser, wantUser)
	}

	if _, err := FilterXattrList(names, userCreds, 5); !linuxerr.Equals(linuxerr.ERANGE, err) {
		t.Fatalf("FilterXattrList small size = %v, want ERANGE", err)
	}
}

func TestXattrPermissionAndFinishHelpers(t *testing.T) {
	t.Parallel()
	userCreds := auth.NewUserCredentials(1000, 1000, nil, nil, auth.NewRootUserNamespace())
	otherCreds := auth.NewUserCredentials(2000, 2000, nil, nil, auth.NewRootUserNamespace())
	mode := linux.FileMode(linux.S_IFREG | 0o600)

	if err := CheckGetXattr(userCreds, mode, 1000, 1000, "user.tag"); err != nil {
		t.Fatalf("CheckGetXattr owner: %v", err)
	}
	if err := CheckGetXattr(otherCreds, mode, 1000, 1000, "user.tag"); !linuxerr.Equals(linuxerr.EACCES, err) {
		t.Fatalf("CheckGetXattr non-owner = %v, want EACCES", err)
	}
	if err := CheckGetXattr(userCreds, mode, 1000, 1000, "badprefix"); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
		t.Fatalf("CheckGetXattr invalid prefix = %v, want EOPNOTSUPP", err)
	}

	val, err := FinishGetXattr(userCreds, &vfs.GetXattrOptions{Name: "user.tag", Size: 4}, []byte("abcd"))
	if err != nil || val != "abcd" {
		t.Fatalf("FinishGetXattr = (%q, %v), want (\"abcd\", nil)", val, err)
	}
	if _, err := FinishGetXattr(userCreds, &vfs.GetXattrOptions{Name: "user.tag", Size: 3}, []byte("abcd")); !linuxerr.Equals(linuxerr.ERANGE, err) {
		t.Fatalf("FinishGetXattr small buffer = %v, want ERANGE", err)
	}

	if err := CheckSetXattr(userCreds, mode, 1000, 1000, "user.tag"); err != nil {
		t.Fatalf("CheckSetXattr owner: %v", err)
	}
	prepared, err := PrepareSetXattrValue(userCreds, 1000, 1000, &vfs.SetXattrOptions{Name: "user.tag", Value: "val"})
	if err != nil || prepared != "val" {
		t.Fatalf("PrepareSetXattrValue = (%q, %v), want (\"val\", nil)", prepared, err)
	}
	if err := CheckRemoveXattr(otherCreds, mode, 1000, 1000, "user.tag"); !linuxerr.Equals(linuxerr.EACCES, err) {
		t.Fatalf("CheckRemoveXattr non-owner = %v, want EACCES", err)
	}
}

func TestStatxAndSetStatHelpers(t *testing.T) {
	t.Parallel()
	now := time.Unix(1700000000, 123456789)
	nowTS := StatxTimestampFromTime(now)
	if nowTS.Sec != 1700000000 || nowTS.Nsec != 123456789 {
		t.Fatalf("StatxTimestampFromTime = %+v", nowTS)
	}

	utimeNow := linux.StatxTimestamp{Sec: 1, Nsec: linux.UTIME_NOW}
	if got := ResolveStatxTime(utimeNow, now); !got.Equal(now) {
		t.Fatalf("ResolveStatxTime(UTIME_NOW) = %v, want %v", got, now)
	}
	if got := ResolveStatxTimestamp(utimeNow, nowTS); got != nowTS {
		t.Fatalf("ResolveStatxTimestamp(UTIME_NOW) = %+v, want %+v", got, nowTS)
	}

	explicit := linux.StatxTimestamp{Sec: 42, Nsec: 99}
	if got := ResolveStatxTimestamp(explicit, nowTS); got != explicit {
		t.Fatalf("ResolveStatxTimestamp(explicit) = %+v, want %+v", got, explicit)
	}

	st := NewStatx(StatxAttr{
		Blksize:   4096,
		Nlink:     2,
		UID:       1000,
		GID:       1000,
		Mode:      linux.S_IFREG | 0o644,
		Ino:       77,
		Size:      8192,
		Blocks:    16,
		Atime:     nowTS,
		Mtime:     nowTS,
		Ctime:     nowTS,
		Btime:     nowTS,
		DevMajor:  254,
		DevMinor:  1,
		RdevMajor: 1,
		RdevMinor: 3,
	})
	if st.Mask != BasicStatxMask || st.Ino != 77 || st.Size != 8192 || st.DevMajor != 254 || st.RdevMinor != 3 {
		t.Fatalf("NewStatx = %+v", st)
	}

	ctx := context.Background()
	rootCreds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	badMask := vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_BTIME}}
	if err := CheckSetStat(ctx, rootCreds, &badMask, linux.FileMode(linux.S_IFREG|0o644), 0, 0); !linuxerr.Equals(linuxerr.EPERM, err) {
		t.Fatalf("CheckSetStat STATX_BTIME = %v, want EPERM", err)
	}
	if err := CheckTruncateFileType(linux.S_IFDIR | 0o755); !linuxerr.Equals(linuxerr.EISDIR, err) {
		t.Fatalf("CheckTruncateFileType(dir) = %v, want EISDIR", err)
	}
	if err := CheckTruncateFileType(linux.S_IFIFO | 0o644); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("CheckTruncateFileType(FIFO) = %v, want EINVAL", err)
	}
	if err := CheckTruncateFileType(linux.S_IFREG | 0o644); err != nil {
		t.Fatalf("CheckTruncateFileType(reg) = %v, want nil", err)
	}
}

func TestClearSUIDAndSGID(t *testing.T) {
	t.Parallel()
	dirMode := uint32(linux.S_IFDIR | linux.S_ISUID | linux.S_ISGID | 0o755)
	if got := ClearSUIDAndSGID(dirMode); got != dirMode {
		t.Fatalf("ClearSUIDAndSGID(dir) = %#o, want %#o", got, dirMode)
	}
	blkMode := uint32(linux.S_IFBLK | linux.S_ISUID | linux.S_ISGID | 0o755)
	if got := ClearSUIDAndSGID(blkMode); got != uint32(linux.S_IFBLK|0o755) {
		t.Fatalf("ClearSUIDAndSGID(blk) = %#o, want %#o", got, uint32(linux.S_IFBLK|0o755))
	}

	userCreds := auth.NewUserCredentials(1000, 1000, nil, nil, auth.NewRootUserNamespace())
	suidReg := uint32(linux.S_IFREG | linux.S_ISUID | 0o755)
	if got := ClearPrivsMode(userCreds, suidReg, 1000, 1000); got != uint32(linux.S_IFREG|0o755) {
		t.Fatalf("ClearPrivsMode(user) = %#o, want %#o", got, uint32(linux.S_IFREG|0o755))
	}

	rootCreds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	if got := ClearPrivsMode(rootCreds, suidReg, 0, 0); got != suidReg {
		t.Fatalf("ClearPrivsMode(root with CAP_FSETID) = %#o, want %#o", got, suidReg)
	}
}

func TestFallocateHelpers(t *testing.T) {
	t.Parallel()
	op, keepSize, err := ParseFallocateMode(0, HostfsFallocateModes)
	if err != nil || op != FallocateReserve || keepSize {
		t.Fatalf("ParseFallocateMode(0) = (%v, %v, %v)", op, keepSize, err)
	}
	op, keepSize, err = ParseFallocateMode(linux.FALLOC_FL_PUNCH_HOLE|linux.FALLOC_FL_KEEP_SIZE, HostfsFallocateModes)
	if err != nil || op != FallocatePunchHole || !keepSize {
		t.Fatalf("ParseFallocateMode(PUNCH_HOLE|KEEP_SIZE) = (%v, %v, %v)", op, keepSize, err)
	}
	if _, _, err := ParseFallocateMode(linux.FALLOC_FL_PUNCH_HOLE, HostfsFallocateModes); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
		t.Fatalf("ParseFallocateMode(PUNCH_HOLE without KEEP_SIZE) = %v, want EOPNOTSUPP", err)
	}
	if _, _, err := ParseFallocateMode(linux.FALLOC_FL_ZERO_RANGE, HostfsFallocateModes); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
		t.Fatalf("ParseFallocateMode(ZERO_RANGE on hostfs) = %v, want EOPNOTSUPP", err)
	}
	op, keepSize, err = ParseFallocateMode(linux.FALLOC_FL_COLLAPSE_RANGE, Ext4FallocateModes)
	if err != nil || op != FallocateCollapseRange || keepSize {
		t.Fatalf("ParseFallocateMode(COLLAPSE_RANGE on ext4) = (%v, %v, %v)", op, keepSize, err)
	}
	if _, _, err := ParseFallocateMode(linux.FALLOC_FL_COLLAPSE_RANGE|linux.FALLOC_FL_INSERT_RANGE, Ext4FallocateModes); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
		t.Fatalf("ParseFallocateMode(COLLAPSE|INSERT) = %v, want EOPNOTSUPP", err)
	}

	if end, err := CheckFallocateRange(10, 20, math.MaxInt64); err != nil || end != 30 {
		t.Fatalf("CheckFallocateRange(10, 20) = (%d, %v), want (30, nil)", end, err)
	}
	if _, err := CheckFallocateRange(10, 0, math.MaxInt64); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("CheckFallocateRange(10, 0) = %v, want EINVAL", err)
	}
	if _, err := CheckFallocateRange(math.MaxInt64, 2, math.MaxInt64); !linuxerr.Equals(linuxerr.EFBIG, err) {
		t.Fatalf("CheckFallocateRange overflow = %v, want EFBIG", err)
	}

	ls := limits.NewLimitSet()
	ls.Set(limits.FileSize, limits.Limit{Cur: 100, Max: 100}, true)
	limCtx := context.WithValue(context.Background(), limits.CtxLimits, ls)
	if err := CheckFallocateLimit(limCtx, 50, 60, true); !linuxerr.Equals(linuxerr.ErrExceedsFileSizeLimit, err) {
		t.Fatalf("CheckFallocateLimit Exceeded = %v, want ErrExceedsFileSizeLimit", err)
	}
	if err := CheckFallocateLimit(limCtx, 50, 60, false); err != nil {
		t.Fatalf("CheckFallocateLimit checkLimit=false = %v, want nil", err)
	}
}

func TestSeekAndRWFlagHelpers(t *testing.T) {
	t.Parallel()
	sizeFn := func() (int64, error) { return 100, nil }
	if off, err := SeekRegular(10, 25, linux.SEEK_SET, sizeFn); err != nil || off != 25 {
		t.Fatalf("SEEK_SET = (%d, %v), want (25, nil)", off, err)
	}
	if off, err := SeekRegular(10, 15, linux.SEEK_CUR, sizeFn); err != nil || off != 25 {
		t.Fatalf("SEEK_CUR = (%d, %v), want (25, nil)", off, err)
	}
	if off, err := SeekRegular(10, -5, linux.SEEK_END, sizeFn); err != nil || off != 95 {
		t.Fatalf("SEEK_END = (%d, %v), want (95, nil)", off, err)
	}
	if off, err := SeekRegular(10, 40, linux.SEEK_DATA, sizeFn); err != nil || off != 40 {
		t.Fatalf("SEEK_DATA = (%d, %v), want (40, nil)", off, err)
	}
	if off, err := SeekRegular(10, 40, linux.SEEK_HOLE, sizeFn); err != nil || off != 100 {
		t.Fatalf("SEEK_HOLE = (%d, %v), want (100, nil)", off, err)
	}
	if _, err := SeekRegular(10, 100, linux.SEEK_DATA, sizeFn); !linuxerr.Equals(linuxerr.ENXIO, err) {
		t.Fatalf("SEEK_DATA at EOF = %v, want ENXIO", err)
	}
	if _, err := SeekBasic(10, 0, linux.SEEK_DATA, sizeFn); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("SeekBasic(SEEK_DATA) = %v, want EINVAL", err)
	}

	if err := CheckRWFlags(RWFAppend | linux.RWF_DSYNC); err != nil {
		t.Fatalf("CheckRWFlags valid = %v, want nil", err)
	}
	if err := CheckRWFlags(RWFAppend | RWFNoAppend); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("CheckRWFlags APPEND|NOAPPEND = %v, want EINVAL", err)
	}
	if err := CheckRWFlags(0x10000); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
		t.Fatalf("CheckRWFlags unknown = %v, want EOPNOTSUPP", err)
	}
	if !AppendsWrite(linux.O_APPEND, 0) {
		t.Fatal("AppendsWrite(O_APPEND, 0) = false, want true")
	}
	if AppendsWrite(linux.O_APPEND, RWFNoAppend) {
		t.Fatal("AppendsWrite(O_APPEND, RWF_NOAPPEND) = true, want false")
	}
	if !AppendsWrite(0, RWFAppend) {
		t.Fatal("AppendsWrite(0, RWF_APPEND) = false, want true")
	}
	if AppendsWrite(0, 0) {
		t.Fatal("AppendsWrite(0, 0) = true, want false")
	}
}
