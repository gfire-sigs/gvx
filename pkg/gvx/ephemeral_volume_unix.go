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
	"syscall"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func openEphemeralStagingFile(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = root.Close()
	}()

	lockFile, err := root.OpenFile(ephemeralLockFileName, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := flockBlockingExclusive(lockFile); err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	defer func() {
		_ = flockUnlock(lockFile)
		_ = lockFile.Close()
	}()

	sweepOwnedEphemeralStagingLocked(dir, root)

	for range 8 {
		token, err := randomEphemeralToken()
		if err != nil {
			return nil, err
		}
		name := ephemeralStagingPrefix + token + ephemeralStagingSuffix
		f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := root.Remove(name); err != nil {
			_ = f.Close()
			return nil, err
		}
		return f, nil
	}
	return nil, errors.New("exhausted retries allocating unique ephemeral staging file")
}

func sweepOwnedEphemeralStagingLocked(dir string, root *os.Root) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	euid := uint32(os.Geteuid())
	for _, entry := range entries {
		name := entry.Name()
		if !isEphemeralStagingName(name) {
			continue
		}
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st == nil || st.Uid != euid {
			continue
		}
		probe, err := root.OpenFile(name, os.O_RDONLY, 0)
		if err != nil {
			continue
		}
		locked := flockTryExclusive(probe) == nil
		if locked {
			_ = root.Remove(name)
			_ = flockUnlock(probe)
		}
		_ = probe.Close()
	}
}

func flockBlockingExclusive(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	for {
		err := unix.Flock(fd, unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func flockTryExclusive(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func flockUnlock(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	return unix.Flock(fd, unix.LOCK_UN)
}
