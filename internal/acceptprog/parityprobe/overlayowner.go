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

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// overlayOwnerUID is the user that creates files in the overlay, as the
// postgres user of postgres:16-alpine does.
const overlayOwnerUID = 70

// overlayNonRootCreates mounts an overlay whose upper layer lives on the
// filesystem under test, and runs a child as an unprivileged user that creates
// a file, a directory, a UNIX socket, and a symbolic link, and then changes the
// mode of the file and the socket. Linux creates each node with the fsuid and
// fsgid of the child (ovl_override_creds), so the child owns it and the mode
// change succeeds.
func overlayNonRootCreates(p overlayUpperPaths) error {
	base := filepath.Dir(p.upper)
	lower := filepath.Join(base, "own-lower")
	upper := filepath.Join(base, "own-upper")
	work := filepath.Join(base, "own-work")
	for _, d := range []string{lower, upper, work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// The merged root takes the attributes of the upper root, so both allow
	// every user to create entries, as /tmp does.
	for _, d := range []string{lower, upper} {
		if err := os.Chmod(d, 0o1777); err != nil {
			return err
		}
	}
	const mnt = "/ovl/own"
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		return err
	}
	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := syscall.Mount("overlay", mnt, "overlay", 0, opts); err != nil {
		return fmt.Errorf("mount overlay (%s): %w", opts, err)
	}
	defer syscall.Unmount(mnt, 0)
	cmd := exec.Command("/proc/self/exe", "overlay-owner-child", mnt)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: overlayOwnerUID, Gid: overlayOwnerUID}}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("child as uid %d: %v: %s", overlayOwnerUID, err, out)
	}
	for _, name := range []string{"file", "dir", "sock", "link"} {
		var st syscall.Stat_t
		if err := syscall.Lstat(filepath.Join(upper, name), &st); err != nil {
			return fmt.Errorf("upper layer: %w", err)
		}
		if st.Uid != overlayOwnerUID || st.Gid != overlayOwnerUID {
			return fmt.Errorf("upper layer %s has the owner %d:%d, want %d:%d", name, st.Uid, st.Gid, overlayOwnerUID, overlayOwnerUID)
		}
	}
	return nil
}

// overlayOwnerChild is the child side of overlayNonRootCreates.
func overlayOwnerChild(dir string) error {
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(file, 0o640); err != nil {
		return fmt.Errorf("chmod of the new file: %w", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dir"), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(dir, "dir"), 0o750); err != nil {
		return fmt.Errorf("chmod of the new directory: %w", err)
	}
	sock := filepath.Join(dir, "sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return err
	}
	// The parent checks the owner of the socket file after the child ends.
	l.SetUnlinkOnClose(false)
	defer l.Close()
	if err := os.Chmod(sock, 0o777); err != nil {
		return fmt.Errorf("chmod of the new socket: %w", err)
	}
	return os.Symlink("file", filepath.Join(dir, "link"))
}
