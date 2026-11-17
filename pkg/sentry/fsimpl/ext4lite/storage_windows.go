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

package ext4lite

import (
	"errors"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// platformTier is the tier that this operating system offers first.
const platformTier = tierWindows

const errHostDiskFull = windows.ERROR_DISK_FULL

// fileFsFullSizeInformationClass is the FS_INFORMATION_CLASS value
// FileFsFullSizeInformation.
const fileFsFullSizeInformationClass = 7

// fileAllocationInfo mirrors FILE_ALLOCATION_INFO.
type fileAllocationInfo struct {
	AllocationSize int64
}

// fileEndOfFileInfo mirrors FILE_END_OF_FILE_INFO.
type fileEndOfFileInfo struct {
	EndOfFile int64
}

// fileZeroDataInformation mirrors FILE_ZERO_DATA_INFORMATION.
type fileZeroDataInformation struct {
	FileOffset      int64
	BeyondFinalZero int64
}

// fileFsFullSizeInformation mirrors FILE_FS_FULL_SIZE_INFORMATION.
type fileFsFullSizeInformation struct {
	TotalAllocationUnits           int64
	CallerAvailableAllocationUnits int64
	ActualAvailableAllocationUnits int64
	SectorsPerAllocationUnit       uint32
	BytesPerSector                 uint32
}

var procNtQueryVolumeInformationFile = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryVolumeInformationFile")

func platformPunchGranularity() int64 {
	return blockSize
}

// osNativeGrow extends the allocation of the file to off+n bytes with
// FileAllocationInfo and then moves the end of file to the same value.
func osNativeGrow(f *os.File, off, n int64) error {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)

	size := off + n
	alloc := fileAllocationInfo{AllocationSize: size}
	if err := windows.SetFileInformationByHandle(h, windows.FileAllocationInfo, (*byte)(unsafe.Pointer(&alloc)), uint32(unsafe.Sizeof(alloc))); err != nil {
		return err
	}
	eof := fileEndOfFileInfo{EndOfFile: size}
	return windows.SetFileInformationByHandle(h, windows.FileEndOfFileInfo, (*byte)(unsafe.Pointer(&eof)), uint32(unsafe.Sizeof(eof)))
}

// osNativeAllocateRange guarantees physical backing for [off, off+n) on NTFS
// after sparse hole punching.
func osNativeAllocateRange(f *os.File, off, n int64) error {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	fileSize := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	if info.FileAttributes&windows.FILE_ATTRIBUTE_SPARSE_FILE == 0 && off+n <= fileSize {
		return nil
	}
	if avail, err := availBytes(f); err == nil && avail < uint64(n) {
		return windows.ERROR_DISK_FULL
	}
	const chunkSize = 256 << 10
	zero := make([]byte, int(min(n, chunkSize)))
	for pos := int64(0); pos < n; pos += int64(len(zero)) {
		step := zero[:int(min(int64(len(zero)), n-pos))]
		if _, err := f.WriteAt(step, off+pos); err != nil {
			return err
		}
	}
	return nil
}

// osNativePunch marks f sparse once via FSCTL_SET_SPARSE and zeroes [off, off+n)
// via FSCTL_SET_ZERO_DATA so NTFS releases whole sparse clusters.
func osNativePunch(f *os.File, off, n int64) (int64, int64, error) {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return 0, 0, err
	}
	fileSize := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	end := min(off+n, fileSize)
	if off >= end {
		return 0, 0, nil
	}
	var returned uint32
	if info.FileAttributes&windows.FILE_ATTRIBUTE_SPARSE_FILE == 0 {
		if err := windows.DeviceIoControl(h, windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &returned, nil); err != nil {
			return 0, 0, err
		}
	}
	zero := fileZeroDataInformation{FileOffset: off, BeyondFinalZero: end}
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_ZERO_DATA,
		(*byte)(unsafe.Pointer(&zero)), uint32(unsafe.Sizeof(zero)), nil, 0, &returned, nil); err != nil {
		return 0, 0, err
	}
	return off, end - off, nil
}

// nativeUnsupported reports whether err means that the host volume does not
// support allocation changes.
func nativeUnsupported(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_PARAMETER) ||
		errors.Is(err, windows.STATUS_NOT_SUPPORTED)
}

func punchUnsupported(err error) bool {
	return nativeUnsupported(err) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION) ||
		errors.Is(err, windows.ERROR_FILE_SYSTEM_LIMITATION)
}

// lockFile takes an exclusive lock on the whole range of f without blocking.
// It retries briefly so a concurrent probe in ProbeVolumeLock cannot abort
// OpenVolume, and returns errVolumeInUse when another handle holds a lock.
func lockFile(f *os.File) error {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)
	for attempt := range 10 {
		var ol windows.Overlapped
		err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ol)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		if attempt < 9 {
			time.Sleep(time.Millisecond)
		}
	}
	return errVolumeInUse
}

// lockFileShared takes a shared lock on the whole range of f without waiting.
// It retries briefly around transient ProbeVolumeLock probes and returns
// errVolumeInUse when another handle holds an exclusive lock.
func lockFileShared(f *os.File) error {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)
	for attempt := range 10 {
		var ol windows.Overlapped
		err := windows.LockFileEx(h, windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ol)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		if attempt < 9 {
			time.Sleep(time.Millisecond)
		}
	}
	return errVolumeInUse
}

func tryLockExclusive(f *os.File) error {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)
	var ol windows.Overlapped
	err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errVolumeInUse
	}
	return err
}

func tryLockShared(f *os.File) error {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)
	var ol windows.Overlapped
	err := windows.LockFileEx(h, windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errVolumeInUse
	}
	return err
}

// unlockFile releases the lock that lockFile or lockFileShared took.
func unlockFile(f *os.File) error {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)
	var ol windows.Overlapped
	return windows.UnlockFileEx(h, 0, 0xFFFFFFFF, 0xFFFFFFFF, &ol)
}

// removeVolumeFile opens path without handle sharing and marks it for deletion.
// It returns errVolumeInUse when any other handle holds path open.
func removeVolumeFile(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	for attempt := range 5 {
		h, err := windows.CreateFile(p, windows.DELETE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			var remove byte = 1
			setErr := windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &remove, 1)
			closeErr := windows.CloseHandle(h)
			return errors.Join(setErr, closeErr)
		}
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			if attempt < 4 {
				time.Sleep(time.Millisecond)
				continue
			}
			return errVolumeInUse
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return os.ErrNotExist
		}
		return err
	}
	return errVolumeInUse
}

// availBytes returns the space that the caller can still use on the volume of
// f. It queries the handle, so it needs no path.
func availBytes(f *os.File) (uint64, error) {
	h := windows.Handle(f.Fd())
	defer runtime.KeepAlive(f)
	var (
		iosb windows.IO_STATUS_BLOCK
		info fileFsFullSizeInformation
	)
	r, _, _ := procNtQueryVolumeInformationFile.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		fileFsFullSizeInformationClass,
	)
	if st := windows.NTStatus(uint32(r)); st != windows.STATUS_SUCCESS {
		return 0, st
	}
	if info.CallerAvailableAllocationUnits < 0 {
		return 0, nil
	}
	return uint64(info.CallerAvailableAllocationUnits) * uint64(info.SectorsPerAllocationUnit) * uint64(info.BytesPerSector), nil
}
