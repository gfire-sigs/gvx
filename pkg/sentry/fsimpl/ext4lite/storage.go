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
)

// fallbackStep is the growth step of the fallback tier. The fallback tier
// rounds every new file size up to a multiple of this value.
const fallbackStep = 4 << 20

// nativeGrow extends the file by n bytes that start at off, which is the
// current size of the file, and allocates every new byte on the host volume.
// The grown file has the size off+n. The value is a variable so that tests can
// inject a failure. The operating system files set the default value.
var nativeGrow = osNativeGrow

// osHostFile is the hostFile implementation on top of an open *os.File. Every
// method works on the open handle only.
type osHostFile struct {
	f *os.File

	// mu makes the size check and the grow step in EnsureSize one step. A
	// write that extends the file between the two steps would otherwise be
	// lost when the grow step sets a smaller size. EnsureSize and Truncate
	// hold mu for writing, and WriteAt holds it for reading.
	mu sync.RWMutex

	// tier holds a storageTier. It changes at most once, from a native tier
	// to tierFallback.
	tier atomic.Int32

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
	return openHostFile(f, platformTier)
}

// newHostFileForTier is like newHostFile, but it skips the probe and forces
// the tier t. It returns an error when the operating system does not support
// t. Tests use it to run the fallback tier on every host.
func newHostFileForTier(f *os.File, t storageTier) (hostFile, error) {
	if t != tierFallback && t != platformTier {
		return nil, fmt.Errorf("ext4lite: the storage tier %q is not available on this operating system", t)
	}
	return openHostFile(f, t)
}

func openHostFile(f *os.File, t storageTier) (hostFile, error) {
	if err := lockFile(f); err != nil {
		return nil, err
	}
	h := &osHostFile{f: f}
	h.tier.Store(int32(t))
	return h, nil
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
