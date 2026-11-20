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

package erofs

import (
	"encoding/binary"
	"math/bits"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
)

// testBlock is the smallest block size that OpenImage accepts in this build.
var testBlock = int(hostarch.PageSize)

// xattrEntryBytes encodes one on-disk xattr entry, padded to four bytes.
func xattrEntryBytes(index uint8, name, value string) []byte {
	b := []byte{byte(len(name)), index, 0, 0}
	binary.LittleEndian.PutUint16(b[2:], uint16(len(value)))
	b = append(b, name...)
	b = append(b, value...)
	for len(b)%XattrAlign != 0 {
		b = append(b, 0)
	}
	return b
}

// ibodyBytes encodes an inline xattr area with the given shared ids.
func ibodyBytes(shared []uint32, entries ...[]byte) []byte {
	b := make([]byte, XattrIbodyHeaderSize)
	b[4] = byte(len(shared))
	for _, id := range shared {
		b = binary.LittleEndian.AppendUint32(b, id)
	}
	for _, e := range entries {
		b = append(b, e...)
	}
	return b
}

// writeInode writes an extended inode and its xattr area at the given nid.
func writeInode(img []byte, nid uint64, mode uint16, rawBlk uint32, ibody []byte) {
	off := testBlock + int(nid)*(1<<InodeSlotBits)
	ino := img[off : off+InodeExtendedSize]
	binary.LittleEndian.PutUint16(ino[0:], InodeLayoutExtended|InodeDataLayoutFlatPlain<<InodeDataLayoutBit)
	binary.LittleEndian.PutUint16(ino[2:], XattrIcount(uint32(len(ibody))))
	binary.LittleEndian.PutUint16(ino[4:], mode)
	binary.LittleEndian.PutUint32(ino[16:], rawBlk)
	binary.LittleEndian.PutUint32(ino[44:], 1)
	copy(img[off+InodeExtendedSize:], ibody)
}

func openTestImage(t *testing.T, img []byte) *Image {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.erofs")
	if err := os.WriteFile(p, img, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	i, err := OpenImage(f)
	if err != nil {
		t.Fatalf("OpenImage: %v", err)
	}
	t.Cleanup(i.Close)
	return i
}

func TestInodeXattrsAndRdev(t *testing.T) {
	img := make([]byte, 3*testBlock)
	sb := img[SuperBlockOffset:]
	binary.LittleEndian.PutUint32(sb[0:], SuperBlockMagicV1)
	sb[12] = uint8(bits.TrailingZeros(uint(testBlock)))
	binary.LittleEndian.PutUint64(sb[16:], 4)
	binary.LittleEndian.PutUint32(sb[36:], 3)
	binary.LittleEndian.PutUint32(sb[40:], 1)
	binary.LittleEndian.PutUint32(sb[44:], 2)

	// Block 2 is the shared xattr area. Entry 0 sits at id 0.
	copy(img[2*testBlock:], xattrEntryBytes(XattrIndexUser, "shared", "sv"))

	writeInode(img, 0, linux.S_IFDIR|0o755, 0, ibodyBytes([]uint32{0},
		xattrEntryBytes(XattrIndexTrusted, "overlay.opaque", "y"),
		xattrEntryBytes(0, "custom.full", "cv"),
		xattrEntryBytes(XattrIndexPosixACLDefault, "", "acl"),
		xattrEntryBytes(XattrIndexSecurity, "capability", "\x01\x02"),
		xattrEntryBytes(9, "unknown", "skipped"),
	))
	writeInode(img, 16, linux.S_IFCHR|0o600, linux.MakeDeviceID(10, 200), nil)
	writeInode(img, 24, linux.S_IFBLK|0o600, linux.MakeDeviceID(4095, 1048575), nil)
	writeInode(img, 32, linux.S_IFREG|0o644, 0, ibodyBytes(nil, xattrEntryBytes(XattrIndexUser, "ok", "v")))
	writeInode(img, 40, linux.S_IFREG|0o644, 0, ibodyBytes(nil, xattrEntryBytes(XattrLongPrefixFlag|1, "x", "v")))
	// An entry that claims more bytes than the area holds.
	bad := ibodyBytes(nil, xattrEntryBytes(XattrIndexUser, "n", "v"))
	bad[XattrIbodyHeaderSize+2] = 200
	writeInode(img, 48, linux.S_IFREG|0o644, 0, bad)

	i := openTestImage(t, img)

	root, err := i.Inode(0)
	if err != nil {
		t.Fatal(err)
	}
	names, err := root.ListXattrs()
	if err != nil {
		t.Fatalf("ListXattrs: %v", err)
	}
	want := []string{
		"user.shared", "trusted.overlay.opaque", "custom.full", "system.posix_acl_default", "security.capability",
	}
	if !slices.Equal(names, want) {
		t.Errorf("ListXattrs = %q, want %q", names, want)
	}
	for name, value := range map[string]string{
		"user.shared": "sv", "trusted.overlay.opaque": "y", "custom.full": "cv",
		"system.posix_acl_default": "acl", "security.capability": "\x01\x02",
	} {
		got, err := root.GetXattr(name)
		if err != nil || string(got) != value {
			t.Errorf("GetXattr(%q) = %q, %v, want %q", name, got, err, value)
		}
	}
	if _, err := root.GetXattr("user.absent"); !linuxerr.Equals(linuxerr.ENODATA, err) {
		t.Errorf("missing xattr error = %v, want ENODATA", err)
	}
	if _, err := root.GetXattr("unknown"); !linuxerr.Equals(linuxerr.ENODATA, err) {
		t.Errorf("entry with an unknown name index was served: %v", err)
	}

	// The returned value must not alias the image mapping.
	v, _ := root.GetXattr("user.shared")
	v[0] = 'X'
	if again, _ := root.GetXattr("user.shared"); string(again) != "sv" {
		t.Error("GetXattr returned a slice of the image")
	}

	for nid, want := range map[uint64][2]uint32{16: {10, 200}, 24: {4095, 1048575}} {
		ino, err := i.Inode(nid)
		if err != nil {
			t.Fatal(err)
		}
		if major, minor := ino.Rdev(); major != want[0] || minor != want[1] {
			t.Errorf("nid %d Rdev = %d:%d, want %d:%d", nid, major, minor, want[0], want[1])
		}
	}
	plain, err := i.Inode(32)
	if err != nil {
		t.Fatal(err)
	}
	if major, minor := plain.Rdev(); major != 0 || minor != 0 {
		t.Errorf("regular file Rdev = %d:%d", major, minor)
	}
	if names, err := plain.ListXattrs(); err != nil || !slices.Equal(names, []string{"user.ok"}) {
		t.Errorf("inline-only xattrs = %q, %v", names, err)
	}

	long, err := i.Inode(40)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := long.ListXattrs(); !linuxerr.Equals(linuxerr.ENOTSUP, err) {
		t.Errorf("long prefix error = %v, want ENOTSUP", err)
	}
	corrupt, err := i.Inode(48)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := corrupt.ListXattrs(); !linuxerr.Equals(linuxerr.EUCLEAN, err) {
		t.Errorf("corrupt area error = %v, want EUCLEAN", err)
	}
}

func TestXattrIcountMatchesLinuxSizing(t *testing.T) {
	for _, size := range []uint32{12, 16, 32, 100} {
		if got := xattrIbodySize(XattrIcount(size)); got != size {
			t.Errorf("ibody of %d bytes round-trips to %d", size, got)
		}
	}
	if XattrIcount(0) != 0 || xattrIbodySize(0) != 0 {
		t.Error("an empty area must have icount 0")
	}
	if got := XattrEntrySize(len("overlay.opaque"), 1); got != 20 {
		t.Errorf("opaque marker entry is %d bytes, want 20", got)
	}
}
