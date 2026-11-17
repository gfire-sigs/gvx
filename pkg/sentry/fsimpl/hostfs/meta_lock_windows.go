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

//go:build windows

package hostfs

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

// metaLockByteOffset places the Windows byte-range lock at 1 GiB so mandatory
// byte-range locking never blocks ReadAt or WriteAt on the 16-byte sequence
// header at offset 0.
const metaLockByteOffset = 0x40000000

// lockMetaExclusive acquires a blocking exclusive lock on the lock byte of f.
func lockMetaExclusive(f *os.File) error {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)
	ol := windows.Overlapped{Offset: metaLockByteOffset}
	return windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol)
}

// tryLockMetaExclusive attempts to acquire a non-blocking exclusive lock on f.
func tryLockMetaExclusive(f *os.File) (bool, error) {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)
	ol := windows.Overlapped{Offset: metaLockByteOffset}
	err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return false, err
}

// lockMetaShared acquires a blocking shared lock on the lock byte of f.
func lockMetaShared(f *os.File) error {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)
	ol := windows.Overlapped{Offset: metaLockByteOffset}
	return windows.LockFileEx(h, 0, 0, 1, 0, &ol)
}

// unlockMeta releases the lock held on the lock byte of f.
func unlockMeta(f *os.File) error {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)
	ol := windows.Overlapped{Offset: metaLockByteOffset}
	return windows.UnlockFileEx(h, 0, 1, 0, &ol)
}
