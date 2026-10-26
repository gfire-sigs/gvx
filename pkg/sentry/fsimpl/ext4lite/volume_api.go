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
	"os"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
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
	chunkMem chunkcache.ChunkMemoryHolder
	// mounted is set by the first mount. A volume serves one filesystem.
	mounted atomic.Bool
	// dataSync writes the mapped pages of the mounted file system. The mount
	// sets it.
	dataSync atomic.Pointer[dataSyncHook]
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
	if !opts.ReadOnly {
		fresh := size == 0
		if !fresh {
			var err error
			if fresh, err = unfinishedFormat(hf); err != nil {
				return nil, err
			}
		}
		if fresh {
			if err := formatVolume(hf, time.Now()); err != nil {
				return nil, err
			}
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

// BlockExtent is a run of contiguous 4 KiB physical blocks of the image. Block
// is the number of the first block, so the run starts at the byte offset
// Block*4096 of the host file.
type BlockExtent struct {
	Block uint64
	Count uint64
}

// ErrMigrationTrackingOff is the error of DrainDirtyBlocks before
// EnableMigrationTracking.
var ErrMigrationTrackingOff = errors.New("ext4lite: migration tracking is off")

// AllocatedBlocks returns every allocated block of the volume as runs in
// ascending order. The runs cover the metadata blocks of every group, the file
// data, the directory blocks, the extent leaves, and the attribute blocks. A
// pre-copy pass sends these blocks and skips every free block.
//
// Call EnableMigrationTracking before AllocatedBlocks. A write after the
// snapshot then shows up in the next DrainDirtyBlocks. Data that a mounted
// file system still holds in mapped pages is not on the host file yet, and the
// first drain writes it.
func (vol *Volume) AllocatedBlocks() []BlockExtent {
	v := vol.v
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.allocatedExtentsLocked()
}

// EnableMigrationTracking starts to record the blocks that a write changes.
// The record starts empty. A second call keeps the record.
func (vol *Volume) EnableMigrationTracking() {
	v := vol.v
	v.mu.Lock()
	defer v.mu.Unlock()
	v.migTracking = true
	v.migOn.Store(true)
}

// DrainDirtyBlocks writes every dirty state of the volume to the host file and
// returns the blocks that changed since the last drain, or since
// EnableMigrationTracking for the first drain. The runs are in ascending order.
// The drain clears the record, so a block returns again only after a new
// write.
//
// A writer that runs during the drain can change a block after the flush. That
// block stays in the record for the next drain. The final drain of a
// migration therefore needs a stopped guest.
func (vol *Volume) DrainDirtyBlocks() ([]BlockExtent, error) {
	v := vol.v
	v.mu.Lock()
	on := v.migTracking
	v.mu.Unlock()
	if !on {
		return nil, ErrMigrationTrackingOff
	}
	// The mapped pages of a mounted file system go to the host file first.
	// Their writes mark the blocks.
	if h := vol.dataSync.Load(); h != nil {
		if err := h.fn(); err != nil {
			return nil, err
		}
	}
	if err := v.sync(); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.takeDirtyExtentsLocked(), nil
}

// dataSyncHook writes the mapped pages of a mounted file system.
type dataSyncHook struct{ fn func() error }

// trackedFile is the host file of a volume. WriteAt marks the blocks that it
// wrote while a migration tracks the volume. The mark follows the write, so a
// drain that runs between the two sees the block in the next drain at the
// latest.
type trackedFile struct {
	hostFile
	v *volume

	// dataDirty is true while a write of file data waits for a host flush.
	// The ordered mode of the journal reads it.
	dataDirty atomic.Bool

	// pmu protects pending.
	pmu sync.Mutex
	// pending holds the home blocks that a committed transaction could not
	// write yet. A read returns them, so that the engine never sees the stale
	// block on the host file. The next flush writes them again.
	pending map[uint64][]byte
}

// WriteAt implements io.WriterAt. It counts as a write of file data.
func (t *trackedFile) WriteAt(p []byte, off int64) (int, error) {
	t.dataDirty.Store(true)
	return t.writeMeta(p, off)
}

// writeMeta writes metadata. It marks the blocks for a live migration, but it
// does not count as file data that waits for a flush.
func (t *trackedFile) writeMeta(p []byte, off int64) (int, error) {
	n, err := t.hostFile.WriteAt(p, off)
	if n > 0 && t.v.migOn.Load() {
		t.v.mu.Lock()
		if t.v.migTracking {
			t.v.markWrittenLocked(off, n)
		}
		t.v.mu.Unlock()
	}
	return n, err
}

// Sync implements hostFile. The flag clears before the host call, so a write
// that races with the flush keeps the flag.
func (t *trackedFile) Sync() error {
	t.dataDirty.Store(false)
	return t.hostFile.Sync()
}

// ReadAt implements io.ReaderAt. It returns the blocks of a failed home write
// in place of the stale host blocks.
func (t *trackedFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := t.hostFile.ReadAt(p, off)
	t.pmu.Lock()
	defer t.pmu.Unlock()
	if len(t.pending) == 0 {
		return n, err
	}
	for blk, data := range t.pending {
		start := int64(blk) * blockSize
		lo, hi := max(off, start), min(off+int64(len(p)), start+blockSize)
		if lo < hi {
			copy(p[lo-off:hi-off], data[lo-start:hi-start])
		}
	}
	return n, err
}
