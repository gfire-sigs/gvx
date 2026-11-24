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

package gvx

import (
	"errors"
	"os"
	"path/filepath"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func openEphemeralVolumeFile(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if !forceEphemeralStagingFallback.Load() {
		f, err := tryOpenLinuxUnnamedVolume(dir)
		if err == nil {
			return f, nil
		}
		if !ephemeralTmpfileUnsupported(err) {
			return nil, err
		}
	}
	return openEphemeralStagingFile(dir)
}

func tryOpenLinuxUnnamedVolume(dir string) (*os.File, error) {
	for {
		fd, openErr := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
		if errors.Is(openErr, unix.EINTR) {
			continue
		}
		if openErr != nil {
			return nil, openErr
		}
		return os.NewFile(uintptr(fd), filepath.Join(dir, "ephemeral.ext4")), nil
	}
}

func ephemeralTmpfileUnsupported(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EISDIR) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOSYS)
}
