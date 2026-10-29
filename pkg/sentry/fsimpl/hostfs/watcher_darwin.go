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

//go:build darwin

package hostfs

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// The macOS backend registers EVFILT_VNODE filters on descriptors that it
// opens below the pinned directory descriptors. It uses no FSEvents: that
// service needs Mach IPC, which the Seatbelt profile of hostlockdown denies.
// The profile allows file operations below the workspace, which covers openat
// with O_EVTONLY. kqueue and kevent are no file operations.
//
// A directory vnode reports NOTE_WRITE when an entry appears, vanishes, or
// moves. It reports nothing when the content of an entry changes. The backend
// therefore also registers each regular file in a watched directory, so that a
// host write to such a file reaches the guest at once. The kqueue tells only
// which entry to scan. The scan finds the names and sends the events.
//
// The number of registrations is bounded: kqueueMaxChildren for one
// directory, and kqueueMaxRegistrations for the Workspace. An entry that
// the bounds leave out falls back to the timer of the poll backend, which the
// goroutine runs through the timeout of kevent.

const (
	// kqueueMaxChildren bounds the file registrations of one directory.
	kqueueMaxChildren = 256

	// kqueueMaxRegistrations bounds the descriptors that the backend holds.
	kqueueMaxRegistrations = 4096

	// vnodeNotes is the set of vnode changes that wake a scan.
	vnodeNotes = unix.NOTE_WRITE | unix.NOTE_EXTEND | unix.NOTE_ATTRIB | unix.NOTE_DELETE |
		unix.NOTE_RENAME | unix.NOTE_LINK | unix.NOTE_REVOKE

	// wakeIdent identifies the user event that stops the goroutine.
	wakeIdent = 1
)

// kqReg is one descriptor that the kqueue watches.
type kqReg struct {
	fd int
	e  *watchEntry
	// file owns fd when the registration opened an os.File. Otherwise fd is a
	// raw descriptor that the backend closes.
	file *os.File
	// name is the host name of a file below a watched directory, or empty for
	// the watched object itself.
	name string
	id   hostID
}

func (r *kqReg) close() {
	if r.file != nil {
		_ = r.file.Close()
		return
	}
	_ = unix.Close(r.fd)
}

// kqState is the part of the backend that belongs to one entry.
type kqState struct {
	self     *kqReg
	children map[string]*kqReg
}

type kqBackend struct {
	hw *hostWatcher
	kq int
	wg sync.WaitGroup

	mu     sync.Mutex
	regs   map[int]*kqReg
	closed bool
	// fallback holds the entries that the timer must scan, because a bound
	// or a failed open left them without a complete registration.
	fallback map[*watchEntry]struct{}
}

func newWatchBackend(hw *hostWatcher) (watchBackend, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, fmt.Errorf("hostfs: create kqueue: %w", err)
	}
	unix.CloseOnExec(kq)
	wake := unix.Kevent_t{Ident: wakeIdent, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_CLEAR}
	if _, err := kevent(kq, []unix.Kevent_t{wake}, nil, nil); err != nil {
		_ = unix.Close(kq)
		return nil, fmt.Errorf("hostfs: register kqueue wake event: %w", err)
	}
	b := &kqBackend{
		hw:       hw,
		kq:       kq,
		regs:     make(map[int]*kqReg),
		fallback: make(map[*watchEntry]struct{}),
	}
	b.wg.Add(1)
	go b.run()
	return b, nil
}

// kevent calls kevent(2) and repeats it after a signal.
func kevent(kq int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
	for {
		n, err := unix.Kevent(kq, changes, events, timeout)
		if !errors.Is(err, unix.EINTR) {
			return n, err
		}
		if len(events) > 0 {
			// A signal interrupted the wait. The caller decides about a retry.
			return 0, nil
		}
	}
}

func (b *kqBackend) holdsPins() bool { return true }

// register adds the vnode filter for fd. The caller holds b.mu.
func (b *kqBackend) registerLocked(r *kqReg) error {
	ev := unix.Kevent_t{
		Ident:  uint64(r.fd),
		Filter: unix.EVFILT_VNODE,
		Flags:  unix.EV_ADD | unix.EV_CLEAR | unix.EV_ENABLE,
		Fflags: vnodeNotes,
	}
	if _, err := kevent(b.kq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		return fmt.Errorf("hostfs: register vnode filter: %w", err)
	}
	b.regs[r.fd] = r
	return nil
}

func (b *kqBackend) add(e *watchEntry) error {
	st := &kqState{children: make(map[string]*kqReg)}
	reg, err := b.openSelf(e)
	if err != nil {
		if e.isDir {
			return err
		}
		// A file that the process cannot open for reading gets the timer.
		b.mu.Lock()
		b.fallback[e] = struct{}{}
		e.backendData = st
		b.mu.Unlock()
		b.wake()
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		reg.close()
		return os.ErrClosed
	}
	if err := b.registerLocked(reg); err != nil {
		reg.close()
		return err
	}
	st.self = reg
	e.backendData = st
	return nil
}

// openSelf opens the descriptor that stands for the watched object.
func (b *kqBackend) openSelf(e *watchEntry) (*kqReg, error) {
	if e.isDir {
		fd, err := openatRetry(int(e.pin.h), ".", unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("hostfs: open watched directory: %w", err)
		}
		return &kqReg{fd: fd, e: e, id: e.ino.id}, nil
	}
	parent, name, ok := e.selfNames()
	if !ok {
		return nil, os.ErrInvalid
	}
	ent, err := e.ws.lookupIn(parent, name)
	if err != nil {
		return nil, err
	}
	f, err := e.ws.openRegularWithAttr(joinRelPath(parent, name), ent, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	return &kqReg{fd: int(f.Fd()), e: e, file: f, id: e.ino.id}, nil
}

func (b *kqBackend) remove(e *watchEntry) {
	b.mu.Lock()
	delete(b.fallback, e)
	st, _ := e.backendData.(*kqState)
	var drop []*kqReg
	if st != nil {
		if st.self != nil {
			drop = append(drop, st.self)
		}
		for _, r := range st.children {
			drop = append(drop, r)
		}
		e.backendData = nil
	}
	for _, r := range drop {
		delete(b.regs, r.fd)
	}
	b.mu.Unlock()
	// Closing a descriptor removes its filters from the kqueue.
	for _, r := range drop {
		r.close()
	}
}

// synced follows the regular files of a watched directory. A new file gets a
// registration, a vanished or replaced file loses its registration.
func (b *kqBackend) synced(e *watchEntry, snap dirSnapshot) {
	if !e.isDir || e.dead.Load() || e.pin == nil {
		return
	}
	b.mu.Lock()
	st, _ := e.backendData.(*kqState)
	if st == nil || b.closed {
		b.mu.Unlock()
		return
	}
	var drop []*kqReg
	for name, r := range st.children {
		if cur, ok := snap.visible(name); !ok || cur.id != r.id || cur.kind != hostKindRegular {
			drop = append(drop, r)
			delete(st.children, name)
			delete(b.regs, r.fd)
		}
	}
	names := make([]string, 0, len(snap))
	for name, cur := range snap {
		if cur.hidden || cur.kind != hostKindRegular {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	complete, stale := true, false
	for _, name := range names {
		if _, ok := st.children[name]; ok {
			continue
		}
		if len(st.children) >= kqueueMaxChildren || len(b.regs) >= kqueueMaxRegistrations {
			complete = false
			break
		}
		cur := snap[name]
		fd, err := openatRetry(int(e.pin.h), name, unix.O_EVTONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			complete = false
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || (hostID{dev: uint64(stat.Dev), ino: uint64(stat.Ino)}) != cur.id {
			_ = unix.Close(fd)
			complete = false
			continue
		}
		r := &kqReg{fd: fd, e: e, name: name, id: cur.id}
		if err := b.registerLocked(r); err != nil {
			_ = unix.Close(fd)
			complete = false
			continue
		}
		st.children[name] = r
		// A write between the scan and the registration raised no event.
		if stat.Size != cur.size || unix.TimespecToNsec(stat.Mtim) != cur.mtime {
			stale = true
		}
	}
	if complete {
		delete(b.fallback, e)
	} else {
		b.fallback[e] = struct{}{}
	}
	b.mu.Unlock()
	if stale {
		e.scheduleRetry()
	}
	if !complete {
		b.wake()
	}
	for _, r := range drop {
		r.close()
	}
}

// wake interrupts the wait of the goroutine, so that it reads the state of
// the fallback set again.
func (b *kqBackend) wake() {
	trigger := unix.Kevent_t{Ident: wakeIdent, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER}
	_, _ = kevent(b.kq, []unix.Kevent_t{trigger}, nil, nil)
}

func (b *kqBackend) run() {
	defer b.wg.Done()
	var events [64]unix.Kevent_t
	// next is the time of the next scan of the fallback entries. Events do
	// not postpone it, so a busy directory cannot starve the others.
	var next time.Time
	for {
		b.mu.Lock()
		polling := len(b.fallback) > 0
		b.mu.Unlock()
		var timeout *unix.Timespec
		var interval time.Duration
		if polling {
			interval = b.hw.pollInterval()
			if next.IsZero() {
				next = time.Now().Add(interval)
			}
			ts := unix.NsecToTimespec(int64(max(time.Until(next), time.Millisecond)))
			timeout = &ts
		} else {
			next = time.Time{}
		}
		n, err := kevent(b.kq, nil, events[:], timeout)
		if err != nil {
			// The descriptor is gone: close ran. Nothing is left to wait for.
			return
		}
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return
		}
		due := make(map[*watchEntry]struct{})
		for _, ev := range events[:n] {
			if ev.Filter != unix.EVFILT_VNODE {
				continue
			}
			if r := b.regs[int(ev.Ident)]; r != nil {
				due[r.e] = struct{}{}
			}
		}
		if polling && !time.Now().Before(next) {
			for e := range b.fallback {
				due[e] = struct{}{}
			}
			next = time.Now().Add(interval)
		}
		b.mu.Unlock()
		list := make([]*watchEntry, 0, len(due))
		for e := range due {
			list = append(list, e)
		}
		slices.SortFunc(list, func(x, y *watchEntry) int { return cmp.Compare(x.seq, y.seq) })
		for _, e := range list {
			b.mu.Lock()
			closed := b.closed
			b.mu.Unlock()
			if closed {
				return
			}
			e.rescan()
		}
	}
}

func (b *kqBackend) close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.wake()
	b.wg.Wait()
	_ = unix.Close(b.kq)
	b.mu.Lock()
	regs := b.regs
	b.regs = make(map[int]*kqReg)
	clear(b.fallback)
	b.mu.Unlock()
	for _, r := range regs {
		r.close()
	}
}

func (b *kqBackend) idle() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.regs) == 0 && len(b.fallback) == 0
}

// kqueueRegistrations reports the descriptors that the backend holds for
// tests.
func (b *kqBackend) kqueueRegistrations() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.regs)
}
