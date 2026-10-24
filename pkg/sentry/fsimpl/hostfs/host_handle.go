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

package hostfs

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

// accessModeMask selects the access mode of the host open flags: os.O_RDONLY,
// os.O_WRONLY, or os.O_RDWR.
const accessModeMask = os.O_RDONLY | os.O_WRONLY | os.O_RDWR

// errHandleBroken reports a host handle that a directory rename closed and
// could not reopen. It wraps os.ErrClosed, so the guest sees EIO.
var errHandleBroken = fmt.Errorf("hostfs: the host file did not reopen after a directory rename: %w", os.ErrClosed)

// hostHandle is a reference-counted host file handle. File descriptions and
// the mapped-page cache share handles, so a mapping can write back after the
// file description that created it closes.
//
// A caller reaches the host file only through acquire and release, or through
// the helpers below that call them. On a host that locks an open directory
// against a move, a directory rename closes and reopens the handles below the
// directory. The rename holds mu for writing from the close to the reopen, so
// no caller ever uses a closed file.
//
// Lock order: Workspace.mu, fileData.dataMu, then hostHandle.mu. While a
// caller holds mu for reading, it calls the host file and takes no other lock
// except a leaf lock. It never takes mu of the same handle again, because a
// waiting writer blocks every later reader.
type hostHandle struct {
	// mu protects f and err.
	mu sync.RWMutex
	f  *os.File
	// err is not nil when the handle cannot reopen. f is closed then, and
	// every use returns err.
	err error
	// dead is set when the last reference dropped and f closed.
	dead bool

	refs atomic.Int32

	// flags is the access mode of the host open. A reopen uses it again.
	flags int

	// owner is the mapped-page cache that uses the handle for write-back.
	// attachHandle sets it. A quiesce flushes the cache before it closes the
	// file.
	owner atomic.Pointer[fileData]

	// reg never changes after the registry adds the handle. reg.mu protects
	// path and seq.
	reg  *winHandleRegistry
	path string
	seq  uint64

	// syncFn replaces File.Sync when set. Tests use it to inject failures.
	syncFn func() error
}

// newHostHandle wraps f, which the host opened with the access mode in
// flags. The handle holds one reference.
func newHostHandle(f *os.File, flags int) *hostHandle {
	h := &hostHandle{f: f, flags: flags & accessModeMask}
	h.refs.Store(1)
	return h
}

func (h *hostHandle) incRef() {
	h.refs.Add(1)
}

// decRef drops one reference. The last reference closes the host file. It
// waits for a directory rename that holds the handle, so the rename never
// reopens a file that the last caller closed.
func (h *hostHandle) decRef() error {
	if h.refs.Add(-1) != 0 {
		return nil
	}
	h.reg.remove(h)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dead = true
	if h.err != nil {
		return nil
	}
	return h.f.Close()
}

// acquire returns the host file with mu held for reading. The caller MUST
// call release after the host call, and only then. It fails when a directory
// rename could not reopen the file.
func (h *hostHandle) acquire() (*os.File, error) {
	h.mu.RLock()
	if h.err != nil {
		err := h.err
		h.mu.RUnlock()
		return nil, err
	}
	return h.f, nil
}

// release ends a use that acquire began.
func (h *hostHandle) release() {
	h.mu.RUnlock()
}

// readAt is File.ReadAt on the live host file.
func (h *hostHandle) readAt(p []byte, off int64) (int, error) {
	f, err := h.acquire()
	if err != nil {
		return 0, err
	}
	n, err := f.ReadAt(p, off)
	h.release()
	return n, err
}

// writeAt is File.WriteAt on the live host file.
func (h *hostHandle) writeAt(p []byte, off int64) (int, error) {
	f, err := h.acquire()
	if err != nil {
		return 0, err
	}
	n, err := f.WriteAt(p, off)
	h.release()
	return n, err
}

// fstat reads the metadata of the live host file.
func (h *hostHandle) fstat(host hostBackend) (hostInfo, error) {
	f, err := h.acquire()
	if err != nil {
		return hostInfo{}, err
	}
	info, err := host.fstat(f)
	h.release()
	return info, err
}

// sync flushes the live host file to stable storage. A host that needs write
// access to flush a handle, such as Windows, skips a read-only handle, because
// that handle never wrote the file.
func (h *hostHandle) sync() error {
	f, err := h.acquire()
	if err != nil {
		return err
	}
	defer h.release()
	if h.syncFn != nil {
		return h.syncFn()
	}
	if flushNeedsWrite && h.flags == os.O_RDONLY {
		return nil
	}
	return f.Sync()
}

// guestEnd ends a guest mutation of ino that went through this handle.
func (h *hostHandle) guestEnd(ino *inode) {
	f, err := h.acquire()
	if err != nil {
		ino.guestEnd(hostInfo{}, false)
		return
	}
	ino.guestEndFile(f)
	h.release()
}
