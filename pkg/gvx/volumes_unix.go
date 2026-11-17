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

//go:build linux || darwin

package gvx

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

var volumeLockProbeMu sync.Mutex

func fileAllocatedBytes(path string, info os.FileInfo) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
		return int64(st.Blocks) * 512
	}
	var ust unix.Stat_t
	if err := unix.Lstat(path, &ust); err == nil {
		return int64(ust.Blocks) * 512
	}
	return info.Size()
}

func flockNonBlock(fd, how int) error {
	for {
		err := unix.Flock(fd, how|unix.LOCK_NB)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func flockUnlock(fd int) error {
	for {
		err := unix.Flock(fd, unix.LOCK_UN)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func probeVolumeLockMode(path string) (string, error) {
	volumeLockProbeMu.Lock()
	defer volumeLockProbeMu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = f.Close()
	}()
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)

	for attempt := range 5 {
		shErr := flockNonBlock(fd, unix.LOCK_SH)
		if shErr != nil {
			if !errors.Is(shErr, unix.EWOULDBLOCK) {
				return "", shErr
			}
			if attempt < 4 {
				time.Sleep(250 * time.Microsecond)
				continue
			}
			return "exclusive", nil
		}
		exErr := flockNonBlock(fd, unix.LOCK_EX)
		_ = flockUnlock(fd)
		if exErr == nil {
			return "none", nil
		}
		if !errors.Is(exErr, unix.EWOULDBLOCK) {
			return "", exErr
		}
		if attempt < 4 {
			time.Sleep(250 * time.Microsecond)
			continue
		}
		return "shared", nil
	}
	return "exclusive", nil
}
