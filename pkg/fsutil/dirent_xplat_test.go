//go:build darwin || linux

package fsutil_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/fsutil"
)

func allocateGuardPagePair(t *testing.T) ([]byte, int) {
	t.Helper()
	pageSize := unix.Getpagesize()
	mem, err := unix.Mmap(-1, 0, 2*pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Munmap(mem)
	})
	if err := unix.Mprotect(mem[pageSize:], unix.PROT_NONE); err != nil {
		t.Fatalf("Mprotect(PROT_NONE): %v", err)
	}
	return mem, pageSize
}

func TestParseDirentsRealRecordAtGuardPageBoundary(t *testing.T) {
	dir := t.TempDir()
	const wantName = "guardprobe"
	if err := os.WriteFile(filepath.Join(dir, wantName), []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	defer unix.Close(dirFD)

	var raw [4096]byte
	n, err := unix.Getdents(dirFD, raw[:])
	if err != nil {
		t.Fatalf("Getdents: %v", err)
	}
	if n <= 0 {
		t.Fatalf("Getdents returned %d bytes, want > 0", n)
	}

	// Locate the real kernel/libc record for wantName in raw[:n].
	const (
		reclenOff = unsafe.Offsetof(unix.Dirent{}.Reclen)
		nameOff   = unsafe.Offsetof(unix.Dirent{}.Name)
	)
	var singleRecord []byte
	var wantIno uint64
	var wantType uint8
	var wantReclen uint16
	cursor := raw[:n]
	fsutil.ParseDirents(cursor, func(ino uint64, _ int64, ftype uint8, name string, reclen uint16) {
		if name != wantName {
			return
		}
		wantIno = ino
		wantType = ftype
		wantReclen = reclen
	})
	for uintptr(len(cursor)) >= nameOff {
		reclen := binary.NativeEndian.Uint16(cursor[reclenOff:])
		if reclen == 0 || int(reclen) > len(cursor) {
			break
		}
		rec := cursor[:reclen]
		cursor = cursor[reclen:]
		var matched bool
		fsutil.ParseDirents(rec, func(_ uint64, _ int64, _ uint8, name string, _ uint16) {
			matched = (name == wantName)
		})
		if matched {
			singleRecord = rec
			break
		}
	}
	if len(singleRecord) == 0 {
		t.Fatalf("did not find real dirent record for %q in %d bytes", wantName, n)
	}
	if len(singleRecord) >= fsutil.UnixDirentMaxSize {
		t.Fatalf("record length %d >= UnixDirentMaxSize %d; expected compact record", len(singleRecord), fsutil.UnixDirentMaxSize)
	}

	// Place the compact real record immediately before a PROT_NONE guard page.
	// Dereferencing *unix.Dirent (1048 bytes on Darwin, 280 bytes on Linux) faults into the guard page.
	mem, pageSize := allocateGuardPagePair(t)
	tail := mem[pageSize-len(singleRecord) : pageSize]
	copy(tail, singleRecord)

	var gotNames []string
	var gotIno uint64
	var gotType uint8
	var gotReclen uint16
	fsutil.ParseDirents(tail, func(ino uint64, _ int64, ftype uint8, name string, reclen uint16) {
		gotNames = append(gotNames, name)
		gotIno = ino
		gotType = ftype
		gotReclen = reclen
	})
	if len(gotNames) != 1 || gotNames[0] != wantName {
		t.Fatalf("ParseDirents names = %v, want [%q]", gotNames, wantName)
	}
	if gotIno != wantIno || gotType != wantType || gotReclen != wantReclen {
		t.Fatalf("ParseDirents metadata = (ino=%d, type=%d, reclen=%d), want (ino=%d, type=%d, reclen=%d)",
			gotIno, gotType, gotReclen, wantIno, wantType, wantReclen)
	}
}

func TestParseDirentsBoundsAndMissingNulAtGuardPage(t *testing.T) {
	const (
		inoOff    = unsafe.Offsetof(unix.Dirent{}.Ino)
		reclenOff = unsafe.Offsetof(unix.Dirent{}.Reclen)
		typeOff   = unsafe.Offsetof(unix.Dirent{}.Type)
		nameOff   = unsafe.Offsetof(unix.Dirent{}.Name)
		recSize   = 32
	)
	mem, pageSize := allocateGuardPagePair(t)
	tail := mem[pageSize-recSize : pageSize]
	clear(tail)

	// Populate a 32-byte dirent with no NUL byte in the name field right before PROT_NONE.
	binary.NativeEndian.PutUint64(tail[inoOff:], 42)
	binary.NativeEndian.PutUint16(tail[reclenOff:], recSize)
	tail[typeOff] = unix.DT_REG
	for i := int(nameOff); i < recSize; i++ {
		tail[i] = 'x'
	}

	var got []string
	fsutil.ParseDirents(tail, func(_ uint64, _ int64, _ uint8, name string, _ uint16) {
		got = append(got, name)
	})
	want := string(tail[nameOff:recSize])
	if len(got) != 1 || got[0] != want {
		t.Fatalf("ParseDirents(no-NUL) = %v, want [%q]", got, want)
	}

	// Verify malformed reclen values (0, < nameOff, > len(buf)) terminate cleanly.
	for _, badReclen := range []uint16{0, uint16(nameOff - 1), recSize + 8} {
		binary.NativeEndian.PutUint16(tail[reclenOff:], badReclen)
		called := false
		fsutil.ParseDirents(tail, func(_ uint64, _ int64, _ uint8, _ string, _ uint16) {
			called = true
		})
		if called {
			t.Fatalf("ParseDirents(reclen=%d) invoked callback on malformed record", badReclen)
		}
	}
}

func TestDirentNamesRealDirectory(t *testing.T) {
	dir := t.TempDir()
	want := []string{"alpha", "beta", "gamma"}
	for _, name := range want {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", name, err)
		}
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	defer unix.Close(dirFD)

	got, err := fsutil.DirentNames(dirFD)
	if err != nil {
		t.Fatalf("DirentNames: %v", err)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("DirentNames = %v, want %v", got, want)
	}
}
