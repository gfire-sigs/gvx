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
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// fallbackStep is the growth step of the fallback tier. The fallback tier
// rounds every new file size up to a multiple of this value.
const fallbackStep = 4 << 20

// nativeGrow extends the file by n bytes that start at off, which is the
// current size of the file, and allocates every new byte on the host volume.
// The grown file has the size off+n. The value is a variable so that tests can
// inject a failure. The operating system files set the default value.
var nativeGrow = osNativeGrow

// nativeAllocateRange ensures physical backing for [off, off+n) inside an
// already-sized host file. Tests replace it to inject host disk-full errors.
var nativeAllocateRange = osNativeAllocateRange

// nativePunch releases physical backing for [off, off+n) without changing the
// file size. Tests replace it to observe or fault-inject punch calls.
var nativePunch = osNativePunch

// probeMu serializes in-process ProbeVolumeLock calls so concurrent goroutines
// probing an idle volume never collide on the transient exclusive lock probe.
var probeMu sync.Mutex

// osHostFile is the hostFile implementation on top of an open *os.File. Every
// method works on the open handle only.
type osHostFile struct {
	f *os.File

	// mu makes the size check and the grow step in EnsureSize one step. A
	// write that extends the file between the two steps would otherwise be
	// lost when the grow step sets a smaller size. EnsureSize and Truncate
	// hold mu for writing, and WriteAt and PunchHole hold it for reading.
	mu sync.RWMutex

	// tier holds a storageTier. It changes at most once, from a native tier
	// to tierFallback.
	tier atomic.Int32

	// punchDisabled becomes true when the host filesystem rejects hole punching.
	punchDisabled atomic.Bool

	closeOnce sync.Once
	closeErr  error
}

var _ hostFile = (*osHostFile)(nil)

// newHostFile takes the exclusive lock of the volume file f and returns a
// hostFile on top of it. It returns errVolumeInUse at once when another
// handle holds the lock. The tier is the native tier of the operating system.
// The first EnsureSize call that has to grow the file probes the host volume
// and downgrades the tier to tierFallback when the volume refuses allocation.
//
// The hostFile owns f after a successful call. When newHostFile fails, the
// caller keeps ownership of f and must close it.
func newHostFile(f *os.File) (hostFile, error) {
	return openHostFile(f, platformTier, false)
}

// newHostFileMode opens f with a shared lock when readOnly is true and an
// exclusive lock otherwise.
func newHostFileMode(f *os.File, readOnly bool) (hostFile, error) {
	return openHostFile(f, platformTier, readOnly)
}

// newHostFileForTier is like newHostFile, but it skips the probe and forces
// the tier t. It returns an error when the operating system does not support
// t. Tests use it to run the fallback tier on every host.
func newHostFileForTier(f *os.File, t storageTier) (hostFile, error) {
	if t != tierFallback && t != platformTier {
		return nil, fmt.Errorf("ext4lite: the storage tier %q is not available on this operating system", t)
	}
	return openHostFile(f, t, false)
}

func openHostFile(f *os.File, t storageTier, readOnly bool) (hostFile, error) {
	var err error
	if readOnly {
		err = lockFileShared(f)
	} else {
		err = lockFile(f)
	}
	if err != nil {
		return nil, err
	}
	h := &osHostFile{f: f}
	h.tier.Store(int32(t))
	return h, nil
}

// probeVolumeLock inspects the advisory OS lock state on path without blocking.
func probeVolumeLock(path string) (VolumeLockMode, error) {
	probeMu.Lock()
	defer probeMu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return VolumeLockNone, err
	}
	defer func() {
		_ = f.Close()
	}()

	for attempt := range 5 {
		err := tryLockExclusive(f)
		if err == nil {
			_ = unlockFile(f)
			return VolumeLockNone, nil
		}
		if !errors.Is(err, errVolumeInUse) {
			return VolumeLockNone, err
		}
		err = tryLockShared(f)
		if err == nil {
			_ = unlockFile(f)
			return VolumeLockShared, nil
		}
		if !errors.Is(err, errVolumeInUse) {
			return VolumeLockNone, err
		}
		if attempt < 4 {
			time.Sleep(300 * time.Microsecond)
		}
	}
	return VolumeLockExclusive, nil
}

// ReadAt reads len(p) bytes at off. It fills the bytes beyond the end of the
// host file with zeros and then reports success.
func (h *osHostFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := h.f.ReadAt(p, off)
	if errors.Is(err, io.EOF) {
		clear(p[n:])
		return len(p), nil
	}
	return n, err
}

// WriteAt writes p at off. A write beyond the end of the file extends the
// file, and the gap before off reads as zeros.
func (h *osHostFile) WriteAt(p []byte, off int64) (int, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.f.WriteAt(p, off)
}

// Sync flushes the file to stable storage.
func (h *osHostFile) Sync() error {
	return h.f.Sync()
}

// Size returns the size of the host file in bytes.
func (h *osHostFile) Size() (int64, error) {
	st, err := h.f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// EnsureSize grows the file to at least size bytes. It never shrinks the file.
func (h *osHostFile) EnsureSize(size int64) error {
	if size < 0 || size > math.MaxInt64-(fallbackStep-1) {
		return fmt.Errorf("ext4lite: invalid volume size %d", size)
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	cur, err := h.Size()
	if err != nil {
		return err
	}
	if cur >= size {
		return nil
	}
	if h.Tier() != tierFallback {
		err := nativeGrow(h.f, cur, size-cur)
		if err == nil {
			return nil
		}
		if !nativeUnsupported(err) {
			return err
		}
		// The host volume refuses allocation. Use ftruncate from now on.
		h.tier.Store(int32(tierFallback))
	}
	target := (size + fallbackStep - 1) &^ (fallbackStep - 1)
	return h.f.Truncate(target)
}

// Truncate sets the size of the file to size.
func (h *osHostFile) Truncate(size int64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.f.Truncate(size)
}

// PunchHole releases physical space in [off, off+length) without changing the
// logical size of the file. Host filesystems that reject hole punching disable
// future punches on this handle and succeed as a no-op.
func (h *osHostFile) PunchHole(off, length int64) error {
	if length <= 0 || off < 0 || h.Tier() == tierFallback || h.punchDisabled.Load() {
		return nil
	}
	h.mu.RLock()
	_, _, err := nativePunch(h.f, off, length)
	h.mu.RUnlock()
	if err == nil {
		return nil
	}
	if punchUnsupported(err) {
		h.punchDisabled.Store(true)
		return nil
	}
	return err
}

// EnsureRange guarantees physical backing for [off, off+length) before a
// previously punched range returns to the allocator.
func (h *osHostFile) EnsureRange(off, length int64) error {
	if length <= 0 {
		return nil
	}
	if off < 0 || length > math.MaxInt64-off {
		return fmt.Errorf("ext4lite: invalid range [%d, +%d)", off, length)
	}
	if h.Tier() == tierFallback {
		if err := h.EnsureSize(off + length); err != nil {
			return err
		}
		if avail, err := h.AvailBytes(); err == nil && avail < uint64(length) {
			return errHostDiskFull
		}
		return nil
	}

	h.mu.RLock()
	cur, err := h.Size()
	if err != nil {
		h.mu.RUnlock()
		return err
	}
	if off+length <= cur {
		err = nativeAllocateRange(h.f, off, length)
		h.mu.RUnlock()
		if err == nil {
			return nil
		}
		if !nativeUnsupported(err) {
			return err
		}
		h.tier.Store(int32(tierFallback))
		if avail, aerr := h.AvailBytes(); aerr == nil && avail < uint64(length) {
			return errHostDiskFull
		}
		return nil
	}
	h.mu.RUnlock()

	if err := h.EnsureSize(off + length); err != nil {
		return err
	}
	if h.Tier() == tierFallback {
		if avail, aerr := h.AvailBytes(); aerr == nil && avail < uint64(length) {
			return errHostDiskFull
		}
		return nil
	}
	h.mu.RLock()
	err = nativeAllocateRange(h.f, off, length)
	h.mu.RUnlock()
	if err != nil && !nativeUnsupported(err) {
		return err
	}
	return nil
}

// PunchGranularity returns the alignment required by PunchHole on this OS.
func (h *osHostFile) PunchGranularity() int64 {
	return platformPunchGranularity()
}

// PunchDisabled reports whether hole punching is unsupported on this handle.
func (h *osHostFile) PunchDisabled() bool {
	return h.Tier() == tierFallback || h.punchDisabled.Load()
}

// AvailBytes returns the free space that the host volume gives to this file.
func (h *osHostFile) AvailBytes() (uint64, error) {
	return availBytes(h.f)
}

// Tier returns the current storage tier.
func (h *osHostFile) Tier() storageTier {
	return storageTier(h.tier.Load())
}

// Close releases the lock and closes the file. Only the first call does work.
// Later calls return the result of the first call.
func (h *osHostFile) Close() error {
	h.closeOnce.Do(func() {
		// Closing the file also drops the lock. The explicit unlock covers
		// a duplicated descriptor that shares the lock.
		_ = unlockFile(h.f)
		h.closeErr = h.f.Close()
	})
	return h.closeErr
}

func punchGranularityOf(hf hostFile) int64 {
	if g, ok := hf.(interface{ PunchGranularity() int64 }); ok {
		return g.PunchGranularity()
	}
	return blockSize
}

func isPunchDisabled(hf hostFile) bool {
	if d, ok := hf.(interface{ PunchDisabled() bool }); ok {
		return d.PunchDisabled()
	}
	return hf.Tier() == tierFallback
}
