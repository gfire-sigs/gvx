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
	"os"
	"sync/atomic"
	"time"
)

// ErrVolumeInUse is the error of OpenVolume when another handle holds the host
// file. Two sandboxes must never write one image.
var ErrVolumeInUse = errVolumeInUse

// VolumeOptions configures OpenVolume.
type VolumeOptions struct {
	// ReadOnly opens the image without any write. It fails when the last mount
	// did not end cleanly.
	ReadOnly bool
}

// Volume is an open image in one host file. The sandbox opens the volume
// before the host lockdown. After the lockdown, the volume needs only reads,
// writes, and the space calls on the file that is already open.
type Volume struct {
	v *volume

	// chunkMem backs the page-cache chunks of mapped files. See SetChunkMemory.
	chunkMem atomic.Pointer[chunkMemoryHolder]
	// mounted is set by the first mount. A volume serves one filesystem.
	mounted atomic.Bool
}

// OpenVolume takes ownership of f. It formats the file as a new volume when
// the file is empty, and it mounts the existing image otherwise. It takes an
// exclusive lock on f and returns ErrVolumeInUse when another handle holds it.
// On an error, OpenVolume closes f.
func OpenVolume(f *os.File, opts VolumeOptions) (*Volume, error) {
	hf, err := newHostFile(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	v, err := mountHostFile(hf, opts)
	if err != nil {
		_ = hf.Close()
		return nil, err
	}
	return &Volume{v: v}, nil
}

func mountHostFile(hf hostFile, opts VolumeOptions) (*volume, error) {
	size, err := hf.Size()
	if err != nil {
		return nil, hostError(err)
	}
	if size == 0 && !opts.ReadOnly {
		if err := formatVolume(hf, time.Now()); err != nil {
			return nil, err
		}
	}
	return openVolume(hf, volumeOptions{readOnly: opts.ReadOnly})
}

// Close performs the clean unmount: it compacts and trims the trailing groups,
// flushes the metadata, truncates the host file, marks the image clean, and
// closes the host file. A second call returns nil.
func (vol *Volume) Close() error {
	return vol.v.close()
}

// Sync writes every dirty metadata block in the required order and flushes the
// host file.
func (vol *Volume) Sync() error {
	return vol.v.sync()
}
