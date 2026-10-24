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

package ext4lite

import (
	"errors"
	"io"
)

// storageTier names how a host file grows and shrinks. The tier depends on
// the host operating system and on what the host volume supports. No tier
// creates a sparse file.
type storageTier int

const (
	// tierNative preallocates space: fallocate on Linux, F_PREALLOCATE on macOS.
	tierNative storageTier = iota
	// tierWindows extends the allocation with FileAllocationInfo and moves the
	// end of file with SetEndOfFile.
	tierWindows
	// tierFallback extends the file with ftruncate in steps. It serves host
	// volumes that refuse preallocation, such as exFAT, FAT32, SMB, and NFS.
	tierFallback
)

// String returns the name of the tier for logs and test messages.
func (t storageTier) String() string {
	switch t {
	case tierNative:
		return "native preallocation"
	case tierWindows:
		return "windows dense allocation"
	case tierFallback:
		return "ftruncate fallback"
	}
	return "unknown tier"
}

// errVolumeInUse reports that another handle holds the exclusive lock of the
// volume file. A second sandbox that mounts the same volume gets this error,
// because two writers would corrupt the image.
var errVolumeInUse = errors.New("ext4lite: the volume file is in use by another sandbox")

// hostFile is the single host file that holds a volume. The sandbox opens it
// before the host lockdown. Every method works on the open handle and makes
// no path-based host call, so the methods keep working after the lockdown.
//
// All methods are safe for concurrent use. ReadAt and WriteAt follow the
// io.ReaderAt and io.WriterAt contracts, except that ReadAt zero-fills the
// bytes of p beyond the end of the host file and returns len(p) with a nil
// error. A read of memory that was never written is therefore a read of zeros.
type hostFile interface {
	io.ReaderAt
	io.WriterAt

	// Sync flushes the file data and metadata to stable storage: fsync on
	// Unix and FlushFileBuffers on Windows.
	Sync() error

	// Size returns the current size of the host file in bytes.
	Size() (int64, error)

	// EnsureSize makes the file at least size bytes long with every byte of
	// the new range allocated on the host volume, without a sparse hole where
	// the host supports allocation. It never shrinks the file. The new bytes
	// read as zeros. The fallback tier extends the file in steps of 4 MiB.
	EnsureSize(size int64) error

	// Truncate sets the size of the file to size. It releases the space of
	// the removed tail on the host volume. Both shrinking and growing work,
	// and growing through Truncate can leave a sparse tail.
	Truncate(size int64) error

	// AvailBytes returns the number of bytes that the host volume can still
	// give to this file.
	AvailBytes() (uint64, error)

	// Tier returns the storage tier that the probe chose.
	Tier() storageTier

	// Close releases the exclusive lock and closes the handle.
	Close() error
}
