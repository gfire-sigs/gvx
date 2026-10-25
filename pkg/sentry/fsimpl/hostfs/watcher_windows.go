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
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows backend posts overlapped ReadDirectoryChangesW calls on handles
// that it opens below the pinned directory handles with NtCreateFile. One
// completion port of its own collects the completions, and one goroutine reads
// them. It does not use the port of the Go runtime, because the runtime gives
// no access to it.
//
// A completion only tells that something in the directory changed. The scan of
// the entry then reads the directory and finds the names, so the buffer of the
// call needs no parsing. A rename shows up as a pair by file identity with
// one shared cookie. A completion with zero bytes means that the buffer
// overflowed (ERROR_NOTIFY_ENUM_DIR). The scan reads the whole directory in
// that case too, so no event is lost.
//
// A watched file is watched through its parent directory.
//
// NTFS refuses to rename or remove a directory with an open handle below it.
// The workspace calls watchQuiesce before such an operation. The backend then
// closes the handles at and below the directory and reopens them after a
// short delay at the path that the dentry names by then. The scan after the
// reopening reports every change that happened in between.

const (
	// watchBufferSize is the size of the buffer of one ReadDirectoryChangesW
	// call.
	watchBufferSize = 64 * 1024

	// watchFilter selects the changes that wake a scan.
	watchFilter = windows.FILE_NOTIFY_CHANGE_FILE_NAME | windows.FILE_NOTIFY_CHANGE_DIR_NAME |
		windows.FILE_NOTIFY_CHANGE_ATTRIBUTES | windows.FILE_NOTIFY_CHANGE_SIZE |
		windows.FILE_NOTIFY_CHANGE_LAST_WRITE | windows.FILE_NOTIFY_CHANGE_CREATION

	// resumeDelay is the time between the closing of the handles for a
	// rename and the next attempt to reopen them.
	resumeDelay = 50 * time.Millisecond

	// maxResumeAttempts bounds the attempts to reopen a handle.
	maxResumeAttempts = 40

	// closeWait bounds the wait for the completion goroutine at shutdown.
	closeWait = 5 * time.Second
)

// winWatch is one directory handle with one outstanding call.
type winWatch struct {
	key    uintptr
	e      *watchEntry
	handle windows.Handle
	// rel is the guest path of the directory that the handle names.
	rel string
	// pending reports that a call is outstanding. The kernel owns buf and ov
	// until its completion packet arrives.
	pending bool
	// dead reports that the backend closed the handle.
	dead bool
	ov   windows.Overlapped
	buf  []uint64
}

type winState struct {
	watch *winWatch
}

type winBackend struct {
	noSync
	hw   *hostWatcher
	iocp windows.Handle
	done chan struct{}

	mu        sync.Mutex
	nextKey   uintptr
	watches   map[uintptr]*winWatch
	closed    bool
	suspended map[*watchEntry]int
	resume    *time.Timer
	// listMu serialises directory listings through pinned handles. A pinned
	// handle keeps one enumeration state.
	listMu sync.Mutex
}

func newWatchBackend(hw *hostWatcher) (watchBackend, error) {
	iocp, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return nil, fmt.Errorf("hostfs: create completion port: %w", err)
	}
	b := &winBackend{
		hw:        hw,
		iocp:      iocp,
		done:      make(chan struct{}),
		watches:   make(map[uintptr]*winWatch),
		suspended: make(map[*watchEntry]int),
	}
	go b.run()
	return b, nil
}

func (b *winBackend) holdsPins() bool { return false }

// openWatchHandle opens the directory that dir names, with list access and
// without the synchronous I/O flag that every other open of hostfs sets, so
// that calls on the handle can run overlapped. The open shares every access
// and never follows a reparse point.
func openWatchHandle(dir windows.Handle) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString("")
	if err != nil {
		return 0, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{
		RootDirectory: dir,
		ObjectName:    objectName,
	}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var handle windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	status := windows.NtCreateFile(
		&handle,
		windows.FILE_LIST_DIRECTORY|windows.SYNCHRONIZE,
		&attrs,
		&iosb,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		fileShareAll,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_OPEN_REPARSE_POINT,
		0,
		0,
	)
	if status != nil {
		return 0, status
	}
	return handle, nil
}

// watchedDirectory returns the guest path of the directory that the entry
// needs: the directory itself, or the parent of a file.
func (e *watchEntry) watchedDirectory() (string, error) {
	if e.isDir {
		return e.dirPath(), nil
	}
	parent, _, ok := e.selfNames()
	if !ok {
		return "", os.ErrInvalid
	}
	return parent, nil
}

func (b *winBackend) add(e *watchEntry) error {
	return b.open(e)
}

// open creates the handle of e and posts the first call.
func (b *winBackend) open(e *watchEntry) error {
	rel, err := e.watchedDirectory()
	if err != nil {
		return err
	}
	unguard := e.ws.watchHandleGuard()
	pin, err := e.ws.acquirePin(rel)
	if err != nil {
		unguard()
		return err
	}
	handle, err := openWatchHandle(windows.Handle(pin.h))
	e.ws.releasePin(pin)
	unguard()
	if err != nil {
		return fmt.Errorf("hostfs: open watch handle: %w", err)
	}
	w := &winWatch{e: e, handle: handle, rel: rel, buf: make([]uint64, watchBufferSize/8)}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		_ = windows.CloseHandle(handle)
		return os.ErrClosed
	}
	b.nextKey++
	w.key = b.nextKey
	if _, err := windows.CreateIoCompletionPort(handle, b.iocp, w.key, 0); err != nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("hostfs: associate watch handle: %w", err)
	}
	b.watches[w.key] = w
	if err := b.postLocked(w); err != nil {
		delete(b.watches, w.key)
		_ = windows.CloseHandle(handle)
		return err
	}
	e.backendData = &winState{watch: w}
	return nil
}

// postLocked starts one ReadDirectoryChangesW call on w.
func (b *winBackend) postLocked(w *winWatch) error {
	w.ov = windows.Overlapped{}
	err := windows.ReadDirectoryChanges(w.handle, (*byte)(unsafe.Pointer(&w.buf[0])), watchBufferSize,
		false, watchFilter, nil, &w.ov, 0)
	if err != nil {
		return fmt.Errorf("hostfs: read directory changes: %w", err)
	}
	w.pending = true
	return nil
}

// closeWatchLocked cancels the call of w and closes the handle. The watch
// stays in the table while a call is outstanding, because the kernel still
// writes to buf and ov until the completion packet arrives.
func (b *winBackend) closeWatchLocked(w *winWatch) {
	if w.dead {
		return
	}
	w.dead = true
	if w.pending {
		_ = windows.CancelIoEx(w.handle, &w.ov)
	}
	_ = windows.CloseHandle(w.handle)
	if !w.pending {
		delete(b.watches, w.key)
	}
}

func (b *winBackend) remove(e *watchEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.suspended, e)
	if st, _ := e.backendData.(*winState); st != nil {
		if st.watch != nil {
			b.closeWatchLocked(st.watch)
		}
		e.backendData = nil
	}
}

// quiesce closes the handles at and below rel and schedules their reopening.
func (b *winBackend) quiesce(rel string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	for _, w := range b.watches {
		if w.dead || !(rel == "." || w.rel == rel || strings.HasPrefix(w.rel, rel+"/")) {
			continue
		}
		b.closeWatchLocked(w)
		if st, _ := w.e.backendData.(*winState); st != nil && st.watch == w {
			st.watch = nil
			b.suspended[w.e] = 0
		}
	}
	b.armResumeLocked()
}

func (b *winBackend) armResumeLocked() {
	if b.resume == nil && len(b.suspended) > 0 {
		b.resume = time.AfterFunc(resumeDelay, b.reopen)
	}
}

// reopen opens the handles that quiesce closed. A scan after each reopening
// reports what changed in the meantime, and it detects a directory that is
// gone.
func (b *winBackend) reopen() {
	b.mu.Lock()
	b.resume = nil
	list := b.suspended
	b.suspended = make(map[*watchEntry]int)
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return
	}
	for e, tries := range list {
		if e.dead.Load() {
			continue
		}
		err := b.open(e)
		switch {
		case err == nil:
			e.rescan()
		case errors.Is(err, fs.ErrNotExist) || tries >= maxResumeAttempts:
			// The directory is gone, or it stays unreachable. A scan that cannot
			// stat it reports the removal, so the guest hears IN_DELETE_SELF.
			e.suspectGone.Store(true)
			e.rescan()
			e.suspectGone.Store(false)
		default:
			b.mu.Lock()
			if !b.closed && !e.dead.Load() {
				b.suspended[e] = tries + 1
				b.armResumeLocked()
			}
			b.mu.Unlock()
		}
	}
}

// run reads the completion packets.
func (b *winBackend) run() {
	defer close(b.done)
	for {
		var n uint32
		var key uintptr
		var ov *windows.Overlapped
		err := windows.GetQueuedCompletionStatus(b.iocp, &n, &key, &ov, windows.INFINITE)
		if ov == nil {
			b.mu.Lock()
			finished := b.closed && len(b.watches) == 0
			b.mu.Unlock()
			if finished || err != nil {
				return
			}
			continue
		}
		b.complete(key, n, err)
		b.mu.Lock()
		finished := b.closed && len(b.watches) == 0
		b.mu.Unlock()
		if finished {
			return
		}
	}
}

// complete handles one completion packet.
func (b *winBackend) complete(key uintptr, n uint32, err error) {
	b.mu.Lock()
	w := b.watches[key]
	if w == nil {
		b.mu.Unlock()
		return
	}
	w.pending = false
	if w.dead || b.closed || errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		// The backend closed the handle. This packet ends the lifetime of w.
		delete(b.watches, key)
		b.mu.Unlock()
		return
	}
	// Post the next call before the scan, so that no change falls in the gap.
	// The buffer content is not needed: the scan reads the directory.
	repost := b.postLocked(w)
	e := w.e
	b.mu.Unlock()
	if repost != nil {
		// The handle is unusable, for example because the directory is gone.
		// One scan reports the outcome.
		b.mu.Lock()
		b.closeWatchLocked(w)
		b.mu.Unlock()
	}
	// ERROR_NOTIFY_ENUM_DIR, ERROR_ACCESS_DENIED, and a zero-byte packet all
	// call for a scan of the whole directory. A handle that fails with an
	// access or handle error and cannot be posted again means that the host
	// removed the directory. The scan then reports the removal even when the
	// stat fails with an error that no not-found code covers.
	lost := repost != nil && (errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_INVALID_HANDLE) ||
		errors.Is(repost, windows.ERROR_ACCESS_DENIED) || errors.Is(repost, windows.ERROR_INVALID_HANDLE))
	if lost {
		e.suspectGone.Store(true)
	}
	e.rescan()
	if lost {
		e.suspectGone.Store(false)
	}
}

func (b *winBackend) close() {
	b.mu.Lock()
	b.closed = true
	if b.resume != nil {
		b.resume.Stop()
		b.resume = nil
	}
	clear(b.suspended)
	for _, w := range b.watches {
		b.closeWatchLocked(w)
	}
	pending := len(b.watches)
	b.mu.Unlock()
	if pending == 0 {
		// The goroutine waits for a packet that no call will produce. Wake it.
		_ = windows.PostQueuedCompletionStatus(b.iocp, 0, 0, nil)
	}
	select {
	case <-b.done:
		_ = windows.CloseHandle(b.iocp)
	case <-time.After(closeWait):
		// A call never completed. Keep the port and the buffers alive: the
		// kernel can still write to them.
	}
}

func (b *winBackend) idle() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.watches) == 0 && len(b.suspended) == 0
}

// listNames lists the host names in the directory that h names. It enumerates
// through the handle, so it needs no path, and it serialises with the other
// listings through pinned handles.
func (w *Workspace) listNames(h hostDirHandle, rel string) ([]string, error) {
	hw := &w.watch
	hw.mu.Lock()
	be, _ := hw.backend.(*winBackend)
	hw.mu.Unlock()
	if be != nil {
		be.listMu.Lock()
		defer be.listMu.Unlock()
	}
	entries, err := readDirHandle(windows.Handle(h), rel)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.name)
	}
	return names, nil
}

// watchHandleGuard keeps a rename or a removal of a directory away while the
// watcher uses a pinned handle. NTFS refuses those operations while any
// handle is open below the directory, and they hold Workspace.mu for writing.
// The caller runs the returned function when it let go of the handle, and it
// takes no call that locks Workspace.mu in between.
func (w *Workspace) watchHandleGuard() func() {
	w.mu.RLock()
	return w.mu.RUnlock
}
