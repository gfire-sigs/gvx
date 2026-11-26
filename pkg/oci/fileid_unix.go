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

package oci

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

const publishViaOpenTempHandle = true

// fileIdentity returns the Unix file identity of f from fstat(2). It rejects
// degenerate identities (zero inode or zero timestamps) so virtual or FAT
// filesystems fall back to full SHA-256 verification.
func fileIdentity(f *os.File) (fileID, bool) {
	rc, err := f.SyscallConn()
	if err != nil {
		return fileID{}, false
	}
	var (
		st      unix.Stat_t
		statErr error
	)
	if err := rc.Control(func(fd uintptr) {
		for {
			statErr = unix.Fstat(int(fd), &st)
			if statErr != unix.EINTR {
				return
			}
		}
	}); err != nil || statErr != nil {
		return fileID{}, false
	}
	runtime.KeepAlive(f)

	dev := uint64(st.Dev)
	ino := uint64(st.Ino)
	mSec, mNsec := int64(st.Mtim.Sec), int64(st.Mtim.Nsec)
	cSec, cNsec := int64(st.Ctim.Sec), int64(st.Ctim.Nsec)
	if ino == 0 || (mSec == 0 && mNsec == 0) || (cSec == 0 && cNsec == 0) {
		return fileID{}, false
	}
	return fileID{
		token:      fmt.Sprintf("u1:%x:%x:%d:%d:%d:%d", dev, ino, mSec, mNsec, cSec, cNsec),
		handleKey:  fmt.Sprintf("u1:%x:%x", dev, ino),
		writeStamp: fmt.Sprintf("%d:%d", mSec, mNsec),
		coarse:     mNsec == 0 && cNsec == 0,
		changeTime: time.Unix(cSec, cNsec),
	}, true
}
