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

//go:build linux

// Command checkpointprobe exercises guest memory mappings, open files on
// hostfs and ext4lite, child network namespaces, ipset state, and forwarded
// TCP sockets across checkpoint and restore.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	heapBufSize       = 64 * 1024
	anonMapSize       = 32 * 1024
	hostfsFileSize    = 8192
	hostfsUnlinkSize  = 4096
	hostfsSeekOffset  = 1337
	hostfsUnlinkSeek  = 512
	ext4RegularSize   = 12288
	ext4UnlinkSize    = 8192
	ext4TmpSize       = 8192
	ext4ExclSize      = 4096
	ext4RegularSeek   = 2048
	ext4UnlinkSeek    = 1024
	ext4TmpSeek       = 768
	ext4ExclSeek      = 256
	forwardedTCPPort  = 8080
	sysctlUnprivPorts = "/proc/sys/net/ipv4/ip_unprivileged_port_start"

	hostfsMapPreBanner     = "HOSTFS-MAP-BEFORE-CKPT"
	hostfsMapPostBanner    = "HOSTFS-MAP-AFTER-RESTORE"
	hostfsOffsetPostBanner = "POST-RESTORE-AT-1401"
	hostfsUnlinkPostBanner = "UNLINKED-AFTER-RESTORE"
	ext4RegularPostBanner  = "EXT4-REGULAR-AFTER-RESTORE"
	ext4UnlinkPostBanner   = "EXT4-UNLINKED-AFTER"
	ext4TmpPostBanner      = "EXT4-TMPFILE-AFTER"

	nfnlSubsysIPSet   = 6
	ipsetProtocol     = 7
	ipsetCmdCreate    = 2
	ipsetCmdAdd       = 9
	ipsetCmdTest      = 11
	ipsetAttrProtocol = 1
	ipsetAttrSetname  = 2
	ipsetAttrTypename = 3
	ipsetAttrRevision = 4
	ipsetAttrFamily   = 5
	ipsetAttrData     = 7
	ipsetAttrIP       = 1
	ipsetAttrIPAddrV4 = 1
	nlaFNested        = 1 << 15
	nlaFNetByteorder  = 1 << 14
	nlaAlignTo        = 4
	soIPSet           = 83
	ipSetOpVersion    = 0x00000100
	ipSetOpGetByName  = 0x00000006
	ipSetMaxNameLen   = 32
	rootIPSetName     = "ckpt_root"
	childIPSetName    = "ckpt_child"
	preCkptPingLine   = "ping-before-ckpt\n"
	preCkptPongLine   = "pong-before-ckpt\n"
	postRestorePing   = "ping-after-restore\n"
	postRestorePong   = "pong-after-restore\n"
)

var stdinReader = bufio.NewReader(os.Stdin)

func main() {
	mode := flag.String("mode", "memory", "verification mode: memory, hostfs, ext4lite, ext4lite-verify, or net")
	workspaceDir := flag.String("workspace", "/workspace", "guest workspace mount path")
	volDir := flag.String("vol", "/mnt/vol", "guest ext4lite mount path")
	flag.Parse()

	var err error
	switch *mode {
	case "memory":
		err = runMemoryMode()
	case "hostfs":
		err = runHostfsMode(*workspaceDir)
	case "ext4lite":
		err = runExt4liteMode(*volDir)
	case "ext4lite-verify":
		err = runExt4liteVerifyMode(*volDir)
	case "net":
		err = runNetMode()
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkpointprobe (%s): %v\n", *mode, err)
		os.Exit(1)
	}
}

func waitForResumeSignal() error {
	line, err := stdinReader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read resume line from stdin: %w", err)
	}
	if strings.TrimSpace(line) == "" {
		return errors.New("received empty resume line on stdin")
	}
	return nil
}

func heapByte(i int) byte {
	return byte((i*73 + 19) ^ (i >> 8))
}

func anonByte(i int) byte {
	return byte((i*41 + 97) ^ (i >> 6))
}

func hostfsOffsetByte(i int) byte {
	return byte((i*29 + 7) & 0xff)
}

func hostfsSharedByte(i int) byte {
	return byte((i*53 + 11) & 0xff)
}

func hostfsUnlinkByte(i int) byte {
	return byte((i*37 + 83) & 0xff)
}

func ext4RegularByte(i int) byte {
	return byte((i*61 + 23) & 0xff)
}

func ext4UnlinkByte(i int) byte {
	return byte((i*47 + 13) & 0xff)
}

func ext4TmpByte(i int) byte {
	return byte((i*17 + 101) & 0xff)
}

func ext4ExclByte(i int) byte {
	return byte((i*19 + 5) & 0xff)
}

func fillPattern(buf []byte, fn func(int) byte) {
	for i := range buf {
		buf[i] = fn(i)
	}
}

func verifyPattern(label string, buf []byte, base int, fn func(int) byte) error {
	for i, got := range buf {
		want := fn(base + i)
		if got != want {
			return fmt.Errorf("%s byte %d (offset %d) = 0x%02x, want 0x%02x", label, i, base+i, got, want)
		}
	}
	return nil
}

func writeAllFD(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func readFullFD(fd int, buf []byte) error {
	off := 0
	for off < len(buf) {
		n, err := unix.Read(fd, buf[off:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		off += n
	}
	return nil
}

func preadFullFD(fd int, buf []byte, offset int64) error {
	off := 0
	for off < len(buf) {
		n, err := unix.Pread(fd, buf[off:], offset+int64(off))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		off += n
	}
	return nil
}

func pwriteAllFD(fd int, data []byte, offset int64) error {
	off := 0
	for off < len(data) {
		n, err := unix.Pwrite(fd, data[off:], offset+int64(off))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		off += n
	}
	return nil
}

func runMemoryMode() error {
	heapBuf := make([]byte, heapBufSize)
	fillPattern(heapBuf, heapByte)

	anonMap, err := unix.Mmap(-1, 0, anonMapSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANONYMOUS|unix.MAP_PRIVATE)
	if err != nil {
		return fmt.Errorf("mmap anonymous region: %w", err)
	}
	defer func() {
		_ = unix.Munmap(anonMap)
	}()
	fillPattern(anonMap, anonByte)

	fmt.Println("READY:memory")
	if err := waitForResumeSignal(); err != nil {
		return err
	}

	if err := verifyPattern("heap", heapBuf, 0, heapByte); err != nil {
		return err
	}
	if err := verifyPattern("anon_mmap", anonMap, 0, anonByte); err != nil {
		return err
	}

	for i := range heapBuf {
		heapBuf[i] ^= 0x5a
	}
	for i := range anonMap {
		anonMap[i] ^= 0xa5
	}
	if err := verifyPattern("heap_mutated", heapBuf, 0, func(i int) byte { return heapByte(i) ^ 0x5a }); err != nil {
		return err
	}
	if err := verifyPattern("anon_mmap_mutated", anonMap, 0, func(i int) byte { return anonByte(i) ^ 0xa5 }); err != nil {
		return err
	}

	runtime.KeepAlive(heapBuf)
	fmt.Println("VERIFIED:memory")
	return nil
}

func runHostfsMode(workspaceDir string) error {
	offsetPath := filepath.Join(workspaceDir, "offset.bin")
	sharedPath := filepath.Join(workspaceDir, "shared.bin")
	unlinkedPath := filepath.Join(workspaceDir, "unlinked.tmp")

	offsetFD, err := unix.Open(offsetPath, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", offsetPath, err)
	}
	defer func() { _ = unix.Close(offsetFD) }()

	offsetInit := make([]byte, hostfsFileSize)
	fillPattern(offsetInit, hostfsOffsetByte)
	if err := writeAllFD(offsetFD, offsetInit); err != nil {
		return fmt.Errorf("write %s: %w", offsetPath, err)
	}
	pos, err := unix.Seek(offsetFD, hostfsSeekOffset, io.SeekStart)
	if err != nil || pos != hostfsSeekOffset {
		return fmt.Errorf("seek %s: pos=%d err=%v", offsetPath, pos, err)
	}

	sharedFD, err := unix.Open(sharedPath, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", sharedPath, err)
	}
	defer func() { _ = unix.Close(sharedFD) }()

	sharedInit := make([]byte, hostfsFileSize)
	fillPattern(sharedInit, hostfsSharedByte)
	if err := writeAllFD(sharedFD, sharedInit); err != nil {
		return fmt.Errorf("write %s: %w", sharedPath, err)
	}
	sharedMap, err := unix.Mmap(sharedFD, 0, hostfsFileSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap MAP_SHARED %s: %w", sharedPath, err)
	}
	defer func() { _ = unix.Munmap(sharedMap) }()

	copy(sharedMap[:len(hostfsMapPreBanner)], hostfsMapPreBanner)
	if err := unix.Msync(sharedMap, unix.MS_SYNC); err != nil {
		return fmt.Errorf("msync pre-checkpoint %s: %w", sharedPath, err)
	}

	unlinkedFD, err := unix.Open(unlinkedPath, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", unlinkedPath, err)
	}
	defer func() { _ = unix.Close(unlinkedFD) }()

	unlinkedInit := make([]byte, hostfsUnlinkSize)
	fillPattern(unlinkedInit, hostfsUnlinkByte)
	if err := writeAllFD(unlinkedFD, unlinkedInit); err != nil {
		return fmt.Errorf("write %s: %w", unlinkedPath, err)
	}
	if err := unix.Unlink(unlinkedPath); err != nil {
		return fmt.Errorf("unlink %s: %w", unlinkedPath, err)
	}
	if err := unix.Access(unlinkedPath, unix.F_OK); !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("access unlinked %s: got %v, want ENOENT", unlinkedPath, err)
	}
	upos, err := unix.Seek(unlinkedFD, hostfsUnlinkSeek, io.SeekStart)
	if err != nil || upos != hostfsUnlinkSeek {
		return fmt.Errorf("seek unlinked fd: pos=%d err=%v", upos, err)
	}

	fmt.Println("READY:hostfs")
	if err := waitForResumeSignal(); err != nil {
		return err
	}

	gotPos, err := unix.Seek(offsetFD, 0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("seek current offset.bin after restore: %w", err)
	}
	if gotPos != hostfsSeekOffset {
		return fmt.Errorf("offset.bin SEEK_CUR after restore = %d, want %d", gotPos, hostfsSeekOffset)
	}
	window := make([]byte, 64)
	if err := readFullFD(offsetFD, window); err != nil {
		return fmt.Errorf("read offset.bin window after restore: %w", err)
	}
	if err := verifyPattern("hostfs_offset_window", window, hostfsSeekOffset, hostfsOffsetByte); err != nil {
		return err
	}
	afterReadPos, err := unix.Seek(offsetFD, 0, io.SeekCurrent)
	if err != nil || afterReadPos != hostfsSeekOffset+int64(len(window)) {
		return fmt.Errorf("offset.bin SEEK_CUR after window read = %d err=%v, want %d", afterReadPos, err, hostfsSeekOffset+len(window))
	}
	if err := writeAllFD(offsetFD, []byte(hostfsOffsetPostBanner)); err != nil {
		return fmt.Errorf("write post-restore banner to offset.bin: %w", err)
	}
	if err := unix.Fsync(offsetFD); err != nil {
		return fmt.Errorf("fsync offset.bin: %w", err)
	}

	gotUnlinkPos, err := unix.Seek(unlinkedFD, 0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("seek current unlinked fd after restore: %w", err)
	}
	if gotUnlinkPos != hostfsUnlinkSeek {
		return fmt.Errorf("unlinked fd SEEK_CUR after restore = %d, want %d", gotUnlinkPos, hostfsUnlinkSeek)
	}
	tail := make([]byte, hostfsUnlinkSize-hostfsUnlinkSeek)
	if err := readFullFD(unlinkedFD, tail); err != nil {
		return fmt.Errorf("read unlinked fd tail after restore: %w", err)
	}
	if err := verifyPattern("hostfs_unlinked_tail", tail, hostfsUnlinkSeek, hostfsUnlinkByte); err != nil {
		return err
	}
	if err := pwriteAllFD(unlinkedFD, []byte(hostfsUnlinkPostBanner), 0); err != nil {
		return fmt.Errorf("pwrite unlinked fd after restore: %w", err)
	}
	fullUnlinked := make([]byte, hostfsUnlinkSize)
	if err := preadFullFD(unlinkedFD, fullUnlinked, 0); err != nil {
		return fmt.Errorf("pread unlinked fd after restore: %w", err)
	}
	if string(fullUnlinked[:len(hostfsUnlinkPostBanner)]) != hostfsUnlinkPostBanner {
		return fmt.Errorf("unlinked fd prefix = %q, want %q", string(fullUnlinked[:len(hostfsUnlinkPostBanner)]), hostfsUnlinkPostBanner)
	}
	if err := verifyPattern("hostfs_unlinked_remainder", fullUnlinked[len(hostfsUnlinkPostBanner):], len(hostfsUnlinkPostBanner), hostfsUnlinkByte); err != nil {
		return err
	}
	if err := unix.Access(unlinkedPath, unix.F_OK); !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("access unlinked path after restore: got %v, want ENOENT", err)
	}

	if string(sharedMap[:len(hostfsMapPreBanner)]) != hostfsMapPreBanner {
		return fmt.Errorf("shared mmap pre-banner = %q, want %q", string(sharedMap[:len(hostfsMapPreBanner)]), hostfsMapPreBanner)
	}
	if err := verifyPattern("hostfs_shared_mmap_mid", sharedMap[len(hostfsMapPreBanner):4096], len(hostfsMapPreBanner), hostfsSharedByte); err != nil {
		return err
	}
	copy(sharedMap[4096:4096+len(hostfsMapPostBanner)], hostfsMapPostBanner)
	if err := unix.Msync(sharedMap, unix.MS_SYNC); err != nil {
		return fmt.Errorf("msync post-restore shared.bin: %w", err)
	}

	fmt.Println("VERIFIED:hostfs")
	return nil
}

func runExt4liteMode(volDir string) error {
	regularPath := filepath.Join(volDir, "regular.dat")
	unlinkedPath := filepath.Join(volDir, "unlinked.dat")
	materializedPath := filepath.Join(volDir, "materialized.dat")
	forbiddenPath := filepath.Join(volDir, "forbidden.dat")

	regularFD, err := unix.Open(regularPath, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", regularPath, err)
	}
	defer func() { _ = unix.Close(regularFD) }()

	regInit := make([]byte, ext4RegularSize)
	fillPattern(regInit, ext4RegularByte)
	if err := writeAllFD(regularFD, regInit); err != nil {
		return fmt.Errorf("write %s: %w", regularPath, err)
	}
	if pos, err := unix.Seek(regularFD, ext4RegularSeek, io.SeekStart); err != nil || pos != ext4RegularSeek {
		return fmt.Errorf("seek %s: pos=%d err=%v", regularPath, pos, err)
	}

	unlinkedFD, err := unix.Open(unlinkedPath, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", unlinkedPath, err)
	}
	defer func() { _ = unix.Close(unlinkedFD) }()

	unlinkInit := make([]byte, ext4UnlinkSize)
	fillPattern(unlinkInit, ext4UnlinkByte)
	if err := writeAllFD(unlinkedFD, unlinkInit); err != nil {
		return fmt.Errorf("write %s: %w", unlinkedPath, err)
	}
	if err := unix.Unlink(unlinkedPath); err != nil {
		return fmt.Errorf("unlink %s: %w", unlinkedPath, err)
	}
	if pos, err := unix.Seek(unlinkedFD, ext4UnlinkSeek, io.SeekStart); err != nil || pos != ext4UnlinkSeek {
		return fmt.Errorf("seek unlinked ext4 fd: pos=%d err=%v", pos, err)
	}

	tmpFD, err := unix.Open(volDir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("open O_TMPFILE on %s: %w", volDir, err)
	}
	defer func() { _ = unix.Close(tmpFD) }()

	tmpInit := make([]byte, ext4TmpSize)
	fillPattern(tmpInit, ext4TmpByte)
	if err := writeAllFD(tmpFD, tmpInit); err != nil {
		return fmt.Errorf("write O_TMPFILE: %w", err)
	}
	if pos, err := unix.Seek(tmpFD, ext4TmpSeek, io.SeekStart); err != nil || pos != ext4TmpSeek {
		return fmt.Errorf("seek O_TMPFILE: pos=%d err=%v", pos, err)
	}

	exclFD, err := unix.Open(volDir, unix.O_TMPFILE|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("open O_TMPFILE|O_EXCL on %s: %w", volDir, err)
	}
	defer func() { _ = unix.Close(exclFD) }()

	exclInit := make([]byte, ext4ExclSize)
	fillPattern(exclInit, ext4ExclByte)
	if err := writeAllFD(exclFD, exclInit); err != nil {
		return fmt.Errorf("write O_TMPFILE|O_EXCL: %w", err)
	}
	if pos, err := unix.Seek(exclFD, ext4ExclSeek, io.SeekStart); err != nil || pos != ext4ExclSeek {
		return fmt.Errorf("seek O_TMPFILE|O_EXCL: pos=%d err=%v", pos, err)
	}

	fmt.Println("READY:ext4lite")
	if err := waitForResumeSignal(); err != nil {
		return err
	}

	regPos, err := unix.Seek(regularFD, 0, io.SeekCurrent)
	if err != nil || regPos != ext4RegularSeek {
		return fmt.Errorf("regular.dat SEEK_CUR after restore = %d err=%v, want %d", regPos, err, ext4RegularSeek)
	}
	regWin := make([]byte, 128)
	if err := readFullFD(regularFD, regWin); err != nil {
		return fmt.Errorf("read regular.dat after restore: %w", err)
	}
	if err := verifyPattern("ext4_regular_window", regWin, ext4RegularSeek, ext4RegularByte); err != nil {
		return err
	}
	if err := pwriteAllFD(regularFD, []byte(ext4RegularPostBanner), ext4RegularSeek); err != nil {
		return fmt.Errorf("pwrite regular.dat after restore: %w", err)
	}
	if err := unix.Fsync(regularFD); err != nil {
		return fmt.Errorf("fsync regular.dat: %w", err)
	}

	unlinkPos, err := unix.Seek(unlinkedFD, 0, io.SeekCurrent)
	if err != nil || unlinkPos != ext4UnlinkSeek {
		return fmt.Errorf("unlinked.dat SEEK_CUR after restore = %d err=%v, want %d", unlinkPos, err, ext4UnlinkSeek)
	}
	var st unix.Stat_t
	if err := unix.Fstat(unlinkedFD, &st); err != nil {
		return fmt.Errorf("fstat unlinked.dat after restore: %w", err)
	}
	if st.Nlink != 0 {
		return fmt.Errorf("unlinked.dat Nlink = %d, want 0", st.Nlink)
	}
	unlinkTail := make([]byte, ext4UnlinkSize-ext4UnlinkSeek)
	if err := readFullFD(unlinkedFD, unlinkTail); err != nil {
		return fmt.Errorf("read unlinked.dat tail after restore: %w", err)
	}
	if err := verifyPattern("ext4_unlinked_tail", unlinkTail, ext4UnlinkSeek, ext4UnlinkByte); err != nil {
		return err
	}
	if err := pwriteAllFD(unlinkedFD, []byte(ext4UnlinkPostBanner), 0); err != nil {
		return fmt.Errorf("pwrite unlinked.dat after restore: %w", err)
	}
	unlinkCheck := make([]byte, len(ext4UnlinkPostBanner))
	if err := preadFullFD(unlinkedFD, unlinkCheck, 0); err != nil {
		return fmt.Errorf("pread unlinked.dat after restore: %w", err)
	}
	if string(unlinkCheck) != ext4UnlinkPostBanner {
		return fmt.Errorf("unlinked.dat prefix = %q, want %q", string(unlinkCheck), ext4UnlinkPostBanner)
	}

	tmpPos, err := unix.Seek(tmpFD, 0, io.SeekCurrent)
	if err != nil || tmpPos != ext4TmpSeek {
		return fmt.Errorf("O_TMPFILE SEEK_CUR after restore = %d err=%v, want %d", tmpPos, err, ext4TmpSeek)
	}
	if err := unix.Fstat(tmpFD, &st); err != nil {
		return fmt.Errorf("fstat O_TMPFILE after restore: %w", err)
	}
	if st.Nlink != 0 {
		return fmt.Errorf("O_TMPFILE Nlink before linkat = %d, want 0", st.Nlink)
	}
	tmpTail := make([]byte, ext4TmpSize-ext4TmpSeek)
	if err := readFullFD(tmpFD, tmpTail); err != nil {
		return fmt.Errorf("read O_TMPFILE tail after restore: %w", err)
	}
	if err := verifyPattern("ext4_tmpfile_tail", tmpTail, ext4TmpSeek, ext4TmpByte); err != nil {
		return err
	}
	if err := pwriteAllFD(tmpFD, []byte(ext4TmpPostBanner), 0); err != nil {
		return fmt.Errorf("pwrite O_TMPFILE after restore: %w", err)
	}
	procTmpPath := fmt.Sprintf("/proc/self/fd/%d", tmpFD)
	if err := unix.Linkat(unix.AT_FDCWD, procTmpPath, unix.AT_FDCWD, materializedPath, unix.AT_SYMLINK_FOLLOW); err != nil {
		return fmt.Errorf("linkat O_TMPFILE to %s: %w", materializedPath, err)
	}
	if err := unix.Fstat(tmpFD, &st); err != nil {
		return fmt.Errorf("fstat O_TMPFILE after linkat: %w", err)
	}
	if st.Nlink != 1 {
		return fmt.Errorf("O_TMPFILE Nlink after linkat = %d, want 1", st.Nlink)
	}
	if err := unix.Fsync(tmpFD); err != nil {
		return fmt.Errorf("fsync O_TMPFILE: %w", err)
	}

	exclPos, err := unix.Seek(exclFD, 0, io.SeekCurrent)
	if err != nil || exclPos != ext4ExclSeek {
		return fmt.Errorf("O_TMPFILE|O_EXCL SEEK_CUR after restore = %d err=%v, want %d", exclPos, err, ext4ExclSeek)
	}
	if err := unix.Fstat(exclFD, &st); err != nil {
		return fmt.Errorf("fstat O_TMPFILE|O_EXCL after restore: %w", err)
	}
	if st.Nlink != 0 {
		return fmt.Errorf("O_TMPFILE|O_EXCL Nlink = %d, want 0", st.Nlink)
	}
	exclTail := make([]byte, ext4ExclSize-ext4ExclSeek)
	if err := readFullFD(exclFD, exclTail); err != nil {
		return fmt.Errorf("read O_TMPFILE|O_EXCL tail after restore: %w", err)
	}
	if err := verifyPattern("ext4_excl_tail", exclTail, ext4ExclSeek, ext4ExclByte); err != nil {
		return err
	}
	procExclPath := fmt.Sprintf("/proc/self/fd/%d", exclFD)
	if err := unix.Linkat(unix.AT_FDCWD, procExclPath, unix.AT_FDCWD, forbiddenPath, unix.AT_SYMLINK_FOLLOW); !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("linkat O_TMPFILE|O_EXCL after restore = %v, want ENOENT", err)
	}

	dirFD, err := unix.Open(volDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open volume dir %s: %w", volDir, err)
	}
	_ = unix.Fsync(dirFD)
	_ = unix.Close(dirFD)
	unix.Sync()

	fmt.Println("VERIFIED:ext4lite")
	return nil
}

func runExt4liteVerifyMode(volDir string) error {
	regularPath := filepath.Join(volDir, "regular.dat")
	unlinkedPath := filepath.Join(volDir, "unlinked.dat")
	materializedPath := filepath.Join(volDir, "materialized.dat")
	forbiddenPath := filepath.Join(volDir, "forbidden.dat")

	regBytes, err := os.ReadFile(regularPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", regularPath, err)
	}
	if len(regBytes) != ext4RegularSize {
		return fmt.Errorf("regular.dat size = %d, want %d", len(regBytes), ext4RegularSize)
	}
	if err := verifyPattern("regular_prefix", regBytes[:ext4RegularSeek], 0, ext4RegularByte); err != nil {
		return err
	}
	gotRegBanner := string(regBytes[ext4RegularSeek : ext4RegularSeek+len(ext4RegularPostBanner)])
	if gotRegBanner != ext4RegularPostBanner {
		return fmt.Errorf("regular.dat post-restore banner = %q, want %q", gotRegBanner, ext4RegularPostBanner)
	}
	afterBanner := ext4RegularSeek + len(ext4RegularPostBanner)
	if err := verifyPattern("regular_suffix", regBytes[afterBanner:], afterBanner, ext4RegularByte); err != nil {
		return err
	}

	matBytes, err := os.ReadFile(materializedPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", materializedPath, err)
	}
	if len(matBytes) != ext4TmpSize {
		return fmt.Errorf("materialized.dat size = %d, want %d", len(matBytes), ext4TmpSize)
	}
	if string(matBytes[:len(ext4TmpPostBanner)]) != ext4TmpPostBanner {
		return fmt.Errorf("materialized.dat prefix = %q, want %q", string(matBytes[:len(ext4TmpPostBanner)]), ext4TmpPostBanner)
	}
	if err := verifyPattern("materialized_suffix", matBytes[len(ext4TmpPostBanner):], len(ext4TmpPostBanner), ext4TmpByte); err != nil {
		return err
	}

	for _, absent := range []string{unlinkedPath, forbiddenPath} {
		if _, err := os.Stat(absent); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s = %v, want not exist", absent, err)
		}
	}

	fmt.Println("VERIFIED:ext4lite-verify")
	return nil
}

type nlAttrBuilder struct {
	b []byte
}

func (a *nlAttrBuilder) put(typ uint16, data []byte) {
	a.b = binary.NativeEndian.AppendUint16(a.b, uint16(4+len(data)))
	a.b = binary.NativeEndian.AppendUint16(a.b, typ)
	a.b = append(a.b, data...)
	for len(a.b)%nlaAlignTo != 0 {
		a.b = append(a.b, 0)
	}
}

func (a *nlAttrBuilder) u8(typ uint16, v uint8) {
	a.put(typ, []byte{v})
}

func (a *nlAttrBuilder) str(typ uint16, s string) {
	a.put(typ, append([]byte(s), 0))
}

func (a *nlAttrBuilder) nest(typ uint16, fn func()) {
	start := len(a.b)
	a.b = binary.NativeEndian.AppendUint16(a.b, 0)
	a.b = binary.NativeEndian.AppendUint16(a.b, typ|nlaFNested)
	fn()
	binary.NativeEndian.PutUint16(a.b[start:], uint16(len(a.b)-start))
}

func ipsetNetlinkExchange(cmd int, flags uint16, seq uint32, build func(a *nlAttrBuilder)) (int32, error) {
	var a nlAttrBuilder
	build(&a)

	msg := make([]byte, 0, 20+len(a.b))
	msg = binary.NativeEndian.AppendUint32(msg, uint32(20+len(a.b)))
	msg = binary.NativeEndian.AppendUint16(msg, uint16(nfnlSubsysIPSet<<8|cmd))
	msg = binary.NativeEndian.AppendUint16(msg, flags)
	msg = binary.NativeEndian.AppendUint32(msg, seq)
	msg = binary.NativeEndian.AppendUint32(msg, 0)
	msg = append(msg, byte(unix.AF_INET), 0, 0, 0)
	msg = append(msg, a.b...)

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return 0, fmt.Errorf("open netfilter netlink socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, fmt.Errorf("bind netfilter netlink socket: %w", err)
	}
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, fmt.Errorf("sendto netfilter netlink socket: %w", err)
	}

	resp := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, resp, 0)
	if err != nil {
		return 0, fmt.Errorf("recvfrom netfilter netlink socket: %w", err)
	}
	if n < 20 {
		return 0, fmt.Errorf("short netlink response (%d bytes)", n)
	}
	msgType := binary.NativeEndian.Uint16(resp[4:6])
	if msgType != unix.NLMSG_ERROR {
		return 0, fmt.Errorf("netlink response type = %d, want NLMSG_ERROR (%d)", msgType, unix.NLMSG_ERROR)
	}
	errno := int32(binary.NativeEndian.Uint32(resp[16:20]))
	return errno, nil
}

func ipsetCreateHashIP(name string, seq uint32) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL)
	errno, err := ipsetNetlinkExchange(ipsetCmdCreate, flags, seq, func(a *nlAttrBuilder) {
		a.u8(ipsetAttrProtocol, ipsetProtocol)
		a.str(ipsetAttrSetname, name)
		a.str(ipsetAttrTypename, "hash:ip")
		a.u8(ipsetAttrRevision, 0)
		a.u8(ipsetAttrFamily, unix.AF_INET)
		a.nest(ipsetAttrData, func() {})
	})
	if err != nil {
		return err
	}
	if errno != 0 {
		return fmt.Errorf("ipset create %q failed with errno %d", name, -errno)
	}
	return nil
}

func ipsetAddIPv4(name string, ip [4]byte, seq uint32) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_EXCL)
	errno, err := ipsetNetlinkExchange(ipsetCmdAdd, flags, seq, func(a *nlAttrBuilder) {
		a.u8(ipsetAttrProtocol, ipsetProtocol)
		a.str(ipsetAttrSetname, name)
		a.nest(ipsetAttrData, func() {
			a.nest(ipsetAttrIP, func() {
				a.put(ipsetAttrIPAddrV4|nlaFNetByteorder, ip[:])
			})
		})
	})
	if err != nil {
		return err
	}
	if errno != 0 {
		return fmt.Errorf("ipset add %v to %q failed with errno %d", ip, name, -errno)
	}
	return nil
}

func ipsetTestIPv4(name string, ip [4]byte, seq uint32) (bool, int32, error) {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	errno, err := ipsetNetlinkExchange(ipsetCmdTest, flags, seq, func(a *nlAttrBuilder) {
		a.u8(ipsetAttrProtocol, ipsetProtocol)
		a.str(ipsetAttrSetname, name)
		a.nest(ipsetAttrData, func() {
			a.nest(ipsetAttrIP, func() {
				a.put(ipsetAttrIPAddrV4|nlaFNetByteorder, ip[:])
			})
		})
	})
	if err != nil {
		return false, 0, err
	}
	return errno == 0, -errno, nil
}

func verifyIPSetSockoptByName(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("open raw inet socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	var verReq [8]byte
	binary.NativeEndian.PutUint32(verReq[0:4], ipSetOpVersion)
	verLen := uint32(len(verReq))
	_, _, e1 := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_IP),
		uintptr(soIPSet),
		uintptr(unsafe.Pointer(&verReq[0])),
		uintptr(unsafe.Pointer(&verLen)),
		0,
	)
	if e1 != 0 {
		return fmt.Errorf("getsockopt SO_IP_SET version: %v", e1)
	}
	if got := binary.NativeEndian.Uint32(verReq[4:8]); got != ipsetProtocol {
		return fmt.Errorf("SO_IP_SET version = %d, want %d", got, ipsetProtocol)
	}

	var nameReq [40]byte
	binary.NativeEndian.PutUint32(nameReq[0:4], ipSetOpGetByName)
	binary.NativeEndian.PutUint32(nameReq[4:8], ipsetProtocol)
	copy(nameReq[8:8+ipSetMaxNameLen], name)
	nameLen := uint32(len(nameReq))
	_, _, e2 := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_IP),
		uintptr(soIPSet),
		uintptr(unsafe.Pointer(&nameReq[0])),
		uintptr(unsafe.Pointer(&nameLen)),
		0,
	)
	if e2 != 0 {
		return fmt.Errorf("getsockopt SO_IP_SET get_byname(%q): %v", name, e2)
	}
	idx := binary.NativeEndian.Uint16(nameReq[8:10])
	if idx == 0xffff {
		return fmt.Errorf("SO_IP_SET get_byname(%q) returned invalid index 0xffff", name)
	}
	return nil
}

func readSysctlTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func threadNetnsInode() (uint64, error) {
	path := fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid())
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return st.Ino, nil
}

func serveSingleTCPExchange(ln net.Listener, wantLine, replyLine string) error {
	conn, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("accept tcp connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read from tcp client: %w", err)
	}
	if got != wantLine {
		return fmt.Errorf("tcp client sent %q, want %q", got, wantLine)
	}
	if _, err := io.WriteString(conn, replyLine); err != nil {
		return fmt.Errorf("write to tcp client: %w", err)
	}
	return nil
}

func runNetMode() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	rootIno, err := threadNetnsInode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(sysctlUnprivPorts, []byte("0\n"), 0o644); err != nil {
		return fmt.Errorf("write root sysctl: %w", err)
	}
	if err := ipsetCreateHashIP(rootIPSetName, 1); err != nil {
		return err
	}
	rootIP1 := [4]byte{10, 88, 1, 9}
	rootIP2 := [4]byte{10, 88, 1, 10}
	childIP1 := [4]byte{10, 99, 2, 7}
	childIP2 := [4]byte{10, 99, 2, 8}

	if err := ipsetAddIPv4(rootIPSetName, rootIP1, 2); err != nil {
		return err
	}
	if ok, code, err := ipsetTestIPv4(rootIPSetName, rootIP1, 3); err != nil || !ok {
		return fmt.Errorf("pre-checkpoint root ipset test %v: ok=%v code=%d err=%v", rootIP1, ok, code, err)
	}
	if ok, _, err := ipsetTestIPv4(rootIPSetName, rootIP2, 4); err != nil || ok {
		return fmt.Errorf("pre-checkpoint root ipset unexpected member %v: ok=%v err=%v", rootIP2, ok, err)
	}
	if err := verifyIPSetSockoptByName(rootIPSetName); err != nil {
		return err
	}

	childReadyCh := make(chan error, 1)
	resumeChildCh := make(chan struct{})
	childDoneCh := make(chan error, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			childReadyCh <- fmt.Errorf("unshare CLONE_NEWNET: %w", err)
			return
		}
		childIno, err := threadNetnsInode()
		if err != nil {
			childReadyCh <- err
			return
		}
		if childIno == rootIno {
			childReadyCh <- fmt.Errorf("child netns inode %d equals root inode", childIno)
			return
		}
		if err := os.WriteFile(sysctlUnprivPorts, []byte("512\n"), 0o644); err != nil {
			childReadyCh <- fmt.Errorf("write child sysctl: %w", err)
			return
		}
		if err := ipsetCreateHashIP(childIPSetName, 10); err != nil {
			childReadyCh <- err
			return
		}
		if err := ipsetAddIPv4(childIPSetName, childIP1, 11); err != nil {
			childReadyCh <- err
			return
		}
		if ok, code, err := ipsetTestIPv4(childIPSetName, childIP1, 12); err != nil || !ok {
			childReadyCh <- fmt.Errorf("pre-checkpoint child ipset test: ok=%v code=%d err=%v", ok, code, err)
			return
		}
		if ok, code, err := ipsetTestIPv4(rootIPSetName, rootIP1, 13); err != nil || ok || code != int32(unix.ENOENT) {
			childReadyCh <- fmt.Errorf("child netns lookup of root ipset: ok=%v code=%d err=%v, want ENOENT", ok, code, err)
			return
		}
		childReadyCh <- nil

		<-resumeChildCh

		postChildIno, err := threadNetnsInode()
		if err != nil {
			childDoneCh <- err
			return
		}
		if postChildIno != childIno {
			childDoneCh <- fmt.Errorf("child netns inode after restore = %d, want %d", postChildIno, childIno)
			return
		}
		gotSysctl, err := readSysctlTrimmed(sysctlUnprivPorts)
		if err != nil {
			childDoneCh <- fmt.Errorf("read child sysctl after restore: %w", err)
			return
		}
		if gotSysctl != "512" {
			childDoneCh <- fmt.Errorf("child sysctl after restore = %q, want 512", gotSysctl)
			return
		}
		if ok, code, err := ipsetTestIPv4(childIPSetName, childIP1, 20); err != nil || !ok {
			childDoneCh <- fmt.Errorf("post-restore child ipset test %v: ok=%v code=%d err=%v", childIP1, ok, code, err)
			return
		}
		if ok, code, err := ipsetTestIPv4(rootIPSetName, rootIP1, 21); err != nil || ok || code != int32(unix.ENOENT) {
			childDoneCh <- fmt.Errorf("post-restore child lookup of root ipset: ok=%v code=%d err=%v, want ENOENT", ok, code, err)
			return
		}
		if err := ipsetAddIPv4(childIPSetName, childIP2, 22); err != nil {
			childDoneCh <- fmt.Errorf("post-restore child ipset add: %w", err)
			return
		}
		if ok, code, err := ipsetTestIPv4(childIPSetName, childIP2, 23); err != nil || !ok {
			childDoneCh <- fmt.Errorf("post-restore child ipset test %v: ok=%v code=%d err=%v", childIP2, ok, code, err)
			return
		}
		if err := verifyIPSetSockoptByName(childIPSetName); err != nil {
			childDoneCh <- fmt.Errorf("post-restore child SO_IP_SET: %w", err)
			return
		}
		childDoneCh <- nil
	}()

	if err := <-childReadyCh; err != nil {
		return err
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", forwardedTCPPort))
	if err != nil {
		return fmt.Errorf("listen tcp4 %d: %w", forwardedTCPPort, err)
	}
	defer func() { _ = ln.Close() }()

	fmt.Println("READY:net")
	if err := serveSingleTCPExchange(ln, preCkptPingLine, preCkptPongLine); err != nil {
		return fmt.Errorf("pre-checkpoint tcp exchange: %w", err)
	}
	fmt.Println("PRE_CONN_DONE:net")

	if err := waitForResumeSignal(); err != nil {
		return err
	}

	close(resumeChildCh)
	if err := <-childDoneCh; err != nil {
		return err
	}

	postRootIno, err := threadNetnsInode()
	if err != nil {
		return err
	}
	if postRootIno != rootIno {
		return fmt.Errorf("root netns inode after restore = %d, want %d", postRootIno, rootIno)
	}
	gotRootSysctl, err := readSysctlTrimmed(sysctlUnprivPorts)
	if err != nil {
		return fmt.Errorf("read root sysctl after restore: %w", err)
	}
	if gotRootSysctl != "0" {
		return fmt.Errorf("root sysctl after restore = %q, want 0", gotRootSysctl)
	}
	if ok, code, err := ipsetTestIPv4(rootIPSetName, rootIP1, 30); err != nil || !ok {
		return fmt.Errorf("post-restore root ipset test %v: ok=%v code=%d err=%v", rootIP1, ok, code, err)
	}
	if ok, code, err := ipsetTestIPv4(childIPSetName, childIP1, 31); err != nil || ok || code != int32(unix.ENOENT) {
		return fmt.Errorf("post-restore root lookup of child ipset: ok=%v code=%d err=%v, want ENOENT", ok, code, err)
	}
	if err := ipsetAddIPv4(rootIPSetName, rootIP2, 32); err != nil {
		return fmt.Errorf("post-restore root ipset add: %w", err)
	}
	if ok, code, err := ipsetTestIPv4(rootIPSetName, rootIP2, 33); err != nil || !ok {
		return fmt.Errorf("post-restore root ipset test %v: ok=%v code=%d err=%v", rootIP2, ok, code, err)
	}
	if err := verifyIPSetSockoptByName(rootIPSetName); err != nil {
		return fmt.Errorf("post-restore root SO_IP_SET: %w", err)
	}

	fmt.Println("READY_POST_CONN:net")
	if err := serveSingleTCPExchange(ln, postRestorePing, postRestorePong); err != nil {
		return fmt.Errorf("post-restore tcp exchange: %w", err)
	}

	fmt.Println("VERIFIED:net")
	return nil
}
