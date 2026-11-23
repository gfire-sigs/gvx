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

// The launcher passes the app cache descriptor to rungv without changing PID.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/internal/androidcache"
)

func main() {
	if err := launch(); err != nil {
		fmt.Fprintf(os.Stderr, "rungv launcher: %v\n", err)
		os.Exit(1)
	}
}

func launch() (err error) {
	if len(os.Args) < 3 || !filepath.IsAbs(os.Args[0]) {
		return errors.New("expected an installed launcher, cache directory and rungv command")
	}
	cachePath := os.Args[1]
	fd, err := unix.Open(cachePath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open app cache: %w", err)
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	if err := androidcache.Verify(fd, cachePath); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
		return fmt.Errorf("pass app cache descriptor: %w", err)
	}
	exe := filepath.Join(filepath.Dir(os.Args[0]), "librungv.so")
	argv := make([]string, 0, len(os.Args)+2)
	argv = append(argv, exe, androidcache.LaunchFlag, strconv.Itoa(fd), cachePath)
	argv = append(argv, os.Args[2:]...)
	return syscall.Exec(exe, argv, os.Environ())
}
