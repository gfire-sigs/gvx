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
	"errors"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func kmsgChecks() []check {
	const path = "/dev/kmsg"
	return []check{
		{"kmsg-is-char-device-1-11", func() error {
			var st unix.Stat_t
			if err := unix.Stat(path, &st); err != nil {
				return err
			}
			if st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(st.Rdev)) != 1 || unix.Minor(uint64(st.Rdev)) != 11 {
				return fmt.Errorf("mode %#o rdev %d:%d, want a character device 1:11", st.Mode, unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)))
			}
			return nil
		}},
		{"kmsg-open-read-write", func() error {
			fd, err := unix.Open(path, unix.O_RDWR, 0)
			if err != nil {
				return err
			}
			return unix.Close(fd)
		}},
		{"kmsg-seek-end-returns-0", func() error {
			fd, err := unix.Open(path, unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			off, err := unix.Seek(fd, 0, unix.SEEK_END)
			if err != nil || off != 0 {
				return fmt.Errorf("lseek(SEEK_END) = %d, %v, want 0", off, err)
			}
			return nil
		}},
		{"kmsg-seek-set-and-data-return-0", func() error {
			fd, err := unix.Open(path, unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			for name, whence := range map[string]int{"SEEK_SET": unix.SEEK_SET, "SEEK_DATA": unix.SEEK_DATA} {
				if off, err := unix.Seek(fd, 0, whence); err != nil || off != 0 {
					return fmt.Errorf("lseek(%s) = %d, %v, want 0", name, off, err)
				}
			}
			return nil
		}},
		{"kmsg-seek-with-offset-fails-with-espipe", func() error {
			fd, err := unix.Open(path, unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			for _, whence := range []int{unix.SEEK_SET, unix.SEEK_DATA, unix.SEEK_END} {
				if off, err := unix.Seek(fd, 1, whence); !errors.Is(err, syscall.ESPIPE) {
					return fmt.Errorf("lseek(1, whence %d) = %d, %v, want ESPIPE", whence, off, err)
				}
			}
			return nil
		}},
		{"kmsg-seek-with-invalid-whence-fails-with-einval", func() error {
			fd, err := unix.Open(path, unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			for _, whence := range []int{unix.SEEK_CUR, unix.SEEK_HOLE, 99} {
				if off, err := unix.Seek(fd, 0, whence); !errors.Is(err, syscall.EINVAL) {
					return fmt.Errorf("lseek(0, whence %d) = %d, %v, want EINVAL", whence, off, err)
				}
			}
			return nil
		}},
		{"kmsg-nonblocking-read-returns-eagain", func() error {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			if _, err := unix.Seek(fd, 0, unix.SEEK_END); err != nil {
				return err
			}
			buf := make([]byte, 8192)
			n, err := unix.Read(fd, buf)
			if !errors.Is(err, syscall.EAGAIN) {
				return fmt.Errorf("read = %d, %v, want EAGAIN", n, err)
			}
			return nil
		}},
		{"kmsg-poll-reports-no-record", func() error {
			fd, err := unix.Open(path, unix.O_RDWR, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLOUT}}
			n, err := unix.Poll(fds, int((50 * time.Millisecond).Milliseconds()))
			if err != nil {
				return err
			}
			if n != 1 || fds[0].Revents != unix.POLLOUT {
				return fmt.Errorf("poll = %d events %#x, want only POLLOUT", n, fds[0].Revents)
			}
			return nil
		}},
		{"kmsg-write-returns-length", func() error {
			fd, err := unix.Open(path, unix.O_WRONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			n, err := unix.Write(fd, []byte("<6>x"))
			if err != nil || n != 4 {
				return fmt.Errorf("write of %q = %d, %v, want 4", "<6>x", n, err)
			}
			return nil
		}},
	}
}
