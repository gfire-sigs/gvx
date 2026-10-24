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
	"errors"
	"io/fs"
	"maps"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// The host watcher turns changes that a host process makes into inotify
// events for the guest. It watches only the directories and files that a guest
// inotify instance watches, and it releases the host resources of an object
// when the last guest watch on it ends.
//
// A host backend only tells the watcher when to look. Each platform has its
// own trigger: a timer on Linux, kqueue on macOS, and ReadDirectoryChangesW
// on Windows. The look is the same everywhere: a scan reads the state of the
// watched object, and a diff against the state of the last scan produces the
// events. The scan of a directory reads every entry, so a move that the host
// made shows up as one vanished name and one new name with the same identity.
//
// Echo suppression. A guest mutation changes the host, and the host trigger
// fires for that change a moment later. The guest already sent its own event.
// Two mechanisms keep the guest from receiving the same change twice:
//
//   - A mutation that changes names (create, unlink, rename, link) calls
//     noteName or noteInode inside the same critical section as the host
//     call. The next scan takes that name out of the diff.
//   - A mutation of file content or times records the host state that it
//     produced in inode.guest. A scan that finds the same state suppresses the
//     event. The record carries a generation counter, so a scan never judges
//     a state while a guest write is in progress.
//
// A change that the guest did not make invalidates the cached state of the
// file before the event reaches the guest: the clean chunks of the mapped-page
// cache and the cached metadata. A guest that reacts to the event therefore
// reads the new bytes.
//
// Lock order: filesystem.mu, then Workspace.mu, then hostWatcher.mu, then
// watchEntry.mu. watchEntry.scanMu is the outermost lock of a scan and never
// nests inside any of the others. The backend locks are leaves.
//
// Known limits:
//
//   - vfs.Inotify.AddWatch cannot fail, so a watch above the cap keeps working
//     for guest events but gets no host events. watchDentry returns ENOSPC
//     and dentry.Watches logs it.
//   - OnZeroWatches can race with an AddWatch that already passed
//     dentry.Watches. The host bridge of that watch then ends early, and a new
//     inotify_add_watch on the same file brings it back.

const (
	// maxWatchedDentries bounds the objects that one Workspace watches on the
	// host. Each directory costs a descriptor on Unix.
	maxWatchedDentries = 8192

	// defaultPollInterval is the time between two scans of the poll backend.
	defaultPollInterval = 200 * time.Millisecond

	// maxScanAttempts is how often one rescan repeats when a guest mutation
	// invalidates the scan. A later retry timer takes over.
	maxScanAttempts = 4

	// scanRetryDelay is the delay before a retry of a rescan that a guest
	// mutation in progress deferred.
	scanRetryDelay = 20 * time.Millisecond

	// cookieBase marks the inotify cookies of host moves. The kernel counts
	// guest cookies up from one, so the two ranges stay apart.
	cookieBase = uint32(1) << 31
)

// watchBackend is the platform part of the host watcher. It decides when a
// watched object needs a scan, and it calls watchEntry.rescan then.
//
// A backend method never blocks on a scan. A scan can wait for filesystem.mu,
// and the caller of remove can hold that lock.
type watchBackend interface {
	// holdsPins reports whether directory entries keep a pinned handle for
	// their lifetime. Backends that scan only after an event do not need one.
	holdsPins() bool
	// add starts the delivery of triggers for e. The caller holds e.scanMu.
	// The baseline scan of e runs after add returns, so no change falls
	// between the registration and the baseline.
	add(e *watchEntry) error
	// remove stops the delivery for e and releases the backend resources of
	// e. The call is not synchronous with a scan that already runs.
	remove(e *watchEntry)
	// synced runs after a committed scan of a directory. A backend uses it to
	// follow the names of the directory. The caller holds e.scanMu.
	synced(e *watchEntry, snap dirSnapshot)
	// close stops every goroutine of the backend, waits for them, and
	// releases every resource.
	close()
	// idle reports that the backend holds no goroutine and no descriptor.
	idle() bool
}

// noSync is the synced method of a backend that does not follow names.
type noSync struct{}

func (noSync) synced(*watchEntry, dirSnapshot) {}

// hostWatcher holds the host watches of one Workspace. The zero value is
// ready for use.
type hostWatcher struct {
	// mu protects the fields below up to the atomics.
	mu       sync.Mutex
	ws       *Workspace
	entries  map[*inode]*watchEntry
	dirs     map[*watchEntry]struct{}
	limit    int
	interval time.Duration
	backend  watchBackend
	closed   bool
	seq      uint64
	warned   bool

	// active is the number of watched objects. Guest mutations read it
	// without a lock to skip all watcher work when it is zero.
	active atomic.Int32
	// cookie counts the cookies of host moves.
	cookie atomic.Uint32
	// delivered counts the notifications that scans handed to the VFS. Tests
	// use it as a barrier.
	delivered atomic.Uint64
	// rejected counts the watches that the cap refused.
	rejected atomic.Uint64
	// teardown tracks the goroutines that close a backend without watches.
	teardown sync.WaitGroup
	// factory replaces newWatchBackend. Tests set it before the first watch.
	factory func(*hostWatcher) (watchBackend, error)
}

func (hw *hostWatcher) limitLocked() int {
	if hw.limit == 0 {
		return maxWatchedDentries
	}
	return hw.limit
}

// pollInterval returns the time between two scans of the poll backend.
func (hw *hostWatcher) pollInterval() time.Duration {
	hw.mu.Lock()
	defer hw.mu.Unlock()
	if hw.interval == 0 {
		return defaultPollInterval
	}
	return hw.interval
}

// setLimit changes the cap of watched objects. Tests use it.
func (hw *hostWatcher) setLimit(n int) {
	hw.mu.Lock()
	hw.limit = n
	hw.mu.Unlock()
}

// setPollInterval changes the time between two scans of the poll backend.
// Call it before the first watch.
func (hw *hostWatcher) setPollInterval(d time.Duration) {
	hw.mu.Lock()
	hw.interval = d
	hw.mu.Unlock()
}

// watchedCount returns the number of watched objects.
func (hw *hostWatcher) watchedCount() int {
	return int(hw.active.Load())
}

func (hw *hostWatcher) nextCookie() uint32 {
	return cookieBase | hw.cookie.Add(1)&^cookieBase
}

// rescanAll scans every watched object once, in the order of registration.
// The timer of the poll backend calls it. Tests call it to run one pass
// without waiting for a trigger.
func (hw *hostWatcher) rescanAll() {
	hw.rescanEntries(hw.snapshotEntries(), nil)
}

func (hw *hostWatcher) snapshotEntries() []*watchEntry {
	hw.mu.Lock()
	list := make([]*watchEntry, 0, len(hw.entries))
	for _, e := range hw.entries {
		list = append(list, e)
	}
	hw.mu.Unlock()
	slices.SortFunc(list, func(a, b *watchEntry) int {
		switch {
		case a.seq < b.seq:
			return -1
		case a.seq > b.seq:
			return 1
		}
		return 0
	})
	return list
}

// rescanEntries scans each entry once and stops early when stop closes.
func (hw *hostWatcher) rescanEntries(list []*watchEntry, stop <-chan struct{}) {
	for _, e := range list {
		select {
		case <-stop:
			return
		default:
		}
		e.rescan()
	}
}

// watchDentry attaches a host watch to the object of d unless one exists. The
// VFS calls dentry.Watches before it adds a guest watch, and so does this
// function. It returns ENOSPC when the cap refuses the object, and the host
// error when the backend cannot watch it.
func (w *Workspace) watchDentry(d *dentry) error {
	ino := d.inode
	if ino.virtual || (ino.kind != hostKindDir && ino.kind != hostKindRegular) {
		return nil
	}
	hw := &w.watch
	hw.mu.Lock()
	if hw.closed || hw.entries[ino] != nil {
		hw.mu.Unlock()
		return nil
	}
	if len(hw.entries) >= hw.limitLocked() {
		hw.rejected.Add(1)
		hw.mu.Unlock()
		return linuxerr.ENOSPC
	}
	if hw.ws == nil {
		hw.ws = w
		hw.entries = make(map[*inode]*watchEntry)
		hw.dirs = make(map[*watchEntry]struct{})
	}
	if hw.backend == nil {
		newBackend := hw.factory
		if newBackend == nil {
			newBackend = newWatchBackend
		}
		be, err := newBackend(hw)
		if err != nil {
			hw.mu.Unlock()
			return err
		}
		hw.backend = be
	}
	be := hw.backend
	hw.seq++
	e := &watchEntry{hw: hw, ws: w, ino: ino, d: d, isDir: ino.kind == hostKindDir, seq: hw.seq}
	hw.entries[ino] = e
	if e.isDir {
		hw.dirs[e] = struct{}{}
	}
	hw.active.Store(int32(len(hw.entries)))
	hw.mu.Unlock()

	e.scanMu.Lock()
	err := e.attach(be)
	e.scanMu.Unlock()
	if err != nil {
		hw.remove(e)
		return err
	}
	return nil
}

// unwatchDentry releases the host watch of d when no guest watch remains. The
// VFS calls it through dentry.OnZeroWatches, possibly with filesystem.mu held.
func (w *Workspace) unwatchDentry(d *dentry) {
	hw := &w.watch
	hw.mu.Lock()
	e := hw.entries[d.inode]
	hw.mu.Unlock()
	if e == nil || d.inode.watches.Size() != 0 {
		return
	}
	hw.remove(e)
}

// watchForget ends the host watch of an inode that no dentry names any more.
// The caller holds filesystem.mu.
//
// A guest rmdir or unlink of a watched object ends here: the dentry dies with
// the removal, so no scan would find the object gone. When the host no longer
// names the object, the guest watchers get IN_DELETE_SELF and IN_IGNORED, as
// on Linux. When the object still exists, the watch just ends. That happens
// when the dentry cache drops an unused dentry.
func (w *Workspace) watchForget(ino *inode) {
	hw := &w.watch
	if hw.active.Load() == 0 {
		return
	}
	hw.mu.Lock()
	e := hw.entries[ino]
	hw.mu.Unlock()
	if e == nil {
		return
	}
	_, exists, err := e.statSelf()
	removed := hw.remove(e)
	if removed && err == nil && !exists {
		ino.invalidateMeta()
		ino.watches.HandleDeletion(context.Background())
	}
}

// remove ends the watch of e and reports whether this call ended it. It is
// safe to call twice: the second call returns false.
func (hw *hostWatcher) remove(e *watchEntry) bool {
	hw.mu.Lock()
	if hw.entries[e.ino] != e {
		hw.mu.Unlock()
		return false
	}
	delete(hw.entries, e.ino)
	delete(hw.dirs, e)
	hw.active.Store(int32(len(hw.entries)))
	be := hw.backend
	var unused watchBackend
	if len(hw.entries) == 0 {
		// The last watch ended. The backend gives back its goroutine and its
		// descriptors. The close runs in a goroutine, because it waits for a
		// scan, and the caller can hold filesystem.mu.
		unused = be
		hw.backend = nil
		hw.teardown.Add(1)
	}
	hw.mu.Unlock()

	e.dead.Store(true)
	if be != nil {
		be.remove(e)
	}
	e.release()
	if unused != nil {
		go func() {
			defer hw.teardown.Done()
			unused.close()
		}()
	}
	return true
}

// watchNoteName records that a guest mutation changed the entry name of the
// directory dir, which the guest names by its path. The caller holds the lock
// that excludes scans, which is Workspace.mu or filesystem.mu.
func (w *Workspace) watchNoteName(dir, name string) {
	hw := &w.watch
	if hw.active.Load() == 0 {
		return
	}
	hw.mu.Lock()
	defer hw.mu.Unlock()
	for e := range hw.dirs {
		if e.d.path() != dir {
			continue
		}
		e.mu.Lock()
		e.gen++
		if e.touched == nil {
			e.touched = make(map[string]struct{})
		}
		e.touched[name] = struct{}{}
		e.mu.Unlock()
	}
}

// watchNoteInode records that a guest mutation changed the link count, the
// name, or the times of ino. The caller holds filesystem.mu.
func (w *Workspace) watchNoteInode(ino *inode) {
	hw := &w.watch
	if hw.active.Load() == 0 {
		return
	}
	hw.mu.Lock()
	defer hw.mu.Unlock()
	if e := hw.entries[ino]; e != nil {
		e.mu.Lock()
		e.gen++
		e.selfTouched = true
		e.mu.Unlock()
	}
}

// watchShutdown ends every host watch and stops the backend. Close calls it
// before it releases the pinned handles.
func (w *Workspace) watchShutdown() {
	hw := &w.watch
	hw.mu.Lock()
	hw.closed = true
	list := make([]*watchEntry, 0, len(hw.entries))
	for _, e := range hw.entries {
		list = append(list, e)
	}
	clear(hw.entries)
	clear(hw.dirs)
	hw.active.Store(0)
	be := hw.backend
	hw.backend = nil
	hw.mu.Unlock()

	for _, e := range list {
		e.dead.Store(true)
	}
	if be != nil {
		be.close()
	}
	hw.teardown.Wait()
	for _, e := range list {
		e.scanMu.Lock()
		e.releaseLocked()
		e.scanMu.Unlock()
	}
}

// quiescer is implemented by a backend whose handles block a directory rename.
type quiescer interface {
	// quiesce closes every host handle of watched objects at or below rel and
	// schedules their reopening.
	quiesce(rel string)
}

// watchQuiesce releases the host handles that would block a rename or a
// removal of the directory rel. Windows refuses to rename a directory with an
// open handle below it. A Unix descriptor follows its directory, so the Unix
// backends do not implement quiescer.
func (w *Workspace) watchQuiesce(rel string) {
	hw := &w.watch
	if hw.active.Load() == 0 {
		return
	}
	hw.mu.Lock()
	be := hw.backend
	hw.mu.Unlock()
	if q, ok := be.(quiescer); ok {
		q.quiesce(rel)
	}
}

// refreshNameCache drops the name snapshot of the guest directory dir. The
// scan found a change by a host process, so the old snapshot is stale. The
// next lookup lists the directory again.
func (w *Workspace) refreshNameCache(dir string) {
	if !w.tracksDirNames() {
		return
	}
	w.nameMu.Lock()
	delete(w.nameCache, dir)
	w.nameMu.Unlock()
}

// guestState records the host state that the last guest mutation of a file
// produced. A scan that finds this state knows that the guest made the
// change.
type guestState struct {
	// gen advances at the start and at the end of each mutation, and inflight
	// counts the mutations that run. A reader that sees the same gen before
	// and after its stat, and sees inflight at zero, read a stable state.
	gen      atomic.Uint64
	inflight atomic.Int32

	mu    sync.Mutex
	valid bool
	mtime int64
	ctime int64
	size  int64
}

func (g *guestState) snapshot() (valid bool, st nameStat) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.valid, nameStat{mtime: g.mtime, ctime: g.ctime, size: g.size}
}

// guestBegin marks the start of a guest mutation of the host file.
func (i *inode) guestBegin() {
	i.guest.inflight.Add(1)
	i.guest.gen.Add(1)
}

// record stores info as the state that a guest mutation produced.
func (g *guestState) record(info hostInfo) {
	g.mu.Lock()
	g.valid = true
	g.mtime = info.mtime.UnixNano()
	g.ctime = info.ctime.UnixNano()
	g.size = info.size
	g.mu.Unlock()
}

// guestEnd ends a mutation. A true ok records info as the state that the
// mutation produced.
func (i *inode) guestEnd(info hostInfo, ok bool) {
	g := &i.guest
	if ok {
		g.record(info)
	}
	g.gen.Add(1)
	g.inflight.Add(-1)
}

// guestEndFile ends a mutation that went through the open host file f. It
// reads the host state only while a watch exists.
func (i *inode) guestEndFile(f *os.File) {
	ws := i.fs.ws
	if ws.watch.active.Load() == 0 {
		i.guestEnd(hostInfo{}, false)
		return
	}
	info, err := ws.host.fstat(f)
	i.guestEnd(info, err == nil)
}

// guestEndPath ends a mutation of the file that the guest path rel names.
func (i *inode) guestEndPath(rel string) {
	ws := i.fs.ws
	if ws.watch.active.Load() == 0 {
		i.guestEnd(hostInfo{}, false)
		return
	}
	e, err := ws.lookupPath(rel)
	i.guestEnd(e.info, err == nil)
}

// logWatchRefusal logs the first watch of a Workspace that got no host events.
func (w *Workspace) logWatchRefusal(d *dentry, err error) {
	hw := &w.watch
	hw.mu.Lock()
	first := !hw.warned
	hw.warned = true
	hw.mu.Unlock()
	if first {
		context.Background().Warningf("hostfs: a guest watch on %q gets no events from host changes: %v", d.path(), err)
	}
}

// watchEntry is the host watch of one inode.
type watchEntry struct {
	hw  *hostWatcher
	ws  *Workspace
	ino *inode
	// d is the dentry that added the watch. The entry reads the current
	// path of the object from it. The entry holds no reference.
	d     *dentry
	isDir bool
	seq   uint64

	dead atomic.Bool

	// scanMu serialises the scans of the entry. It also guards pin.
	scanMu sync.Mutex
	pin    *dirPin

	// mu protects the fields below. A guest mutation takes it while it holds
	// filesystem.mu or Workspace.mu, so nothing blocks while mu is held.
	mu          sync.Mutex
	gen         uint64
	snap        dirSnapshot
	self        nameStat
	touched     map[string]struct{}
	selfTouched bool
	// suspectGone is set by a backend that lost its handle in a way that
	// suggests a removed directory. A scan that cannot stat the object then
	// takes it as gone.
	suspectGone atomic.Bool
	retry       *time.Timer

	// backendData belongs to the backend of the entry. The backend guards it.
	backendData any
}

// dirPath returns the guest path of the watched directory.
func (e *watchEntry) dirPath() string {
	return e.d.path()
}

// selfNames returns the guest path of the parent and the guest name of the
// watched object. The root has no parent and returns ok false.
func (e *watchEntry) selfNames() (parent, name string, ok bool) {
	p, n := e.d.names()
	if p == nil {
		return "", "", false
	}
	return p.path(), n, true
}

// attach registers e with the backend and reads the baseline. The caller holds
// e.scanMu.
func (e *watchEntry) attach(be watchBackend) error {
	if e.isDir && be.holdsPins() {
		pin, err := e.ws.acquirePin(e.dirPath())
		if err != nil {
			return err
		}
		e.pin = pin
	}
	if err := be.add(e); err != nil {
		e.releaseLocked()
		return err
	}
	res := e.scanHost()
	if res.err == nil && !res.exists {
		res.err = fs.ErrNotExist
	}
	if res.err != nil {
		be.remove(e)
		e.releaseLocked()
		return res.err
	}
	e.snap = res.snap
	e.self = res.self
	be.synced(e, res.snap)
	return nil
}

// release gives back the pinned handle and stops the retry timer. It never
// blocks on a scan: when a scan runs, a goroutine waits for it.
func (e *watchEntry) release() {
	if e.scanMu.TryLock() {
		e.releaseLocked()
		e.scanMu.Unlock()
		return
	}
	go func() {
		e.scanMu.Lock()
		e.releaseLocked()
		e.scanMu.Unlock()
	}()
}

// releaseLocked is release for a caller that holds e.scanMu.
func (e *watchEntry) releaseLocked() {
	e.mu.Lock()
	if e.retry != nil {
		e.retry.Stop()
		e.retry = nil
	}
	e.mu.Unlock()
	if e.pin != nil {
		e.ws.releasePin(e.pin)
		e.pin = nil
	}
}

// dirHandle returns the handle of the watched directory. The release function
// gives it back.
func (e *watchEntry) dirHandle() (hostDirHandle, func(), error) {
	if e.pin != nil {
		return e.pin.h, func() {}, nil
	}
	pin, err := e.ws.acquirePin(e.dirPath())
	if err != nil {
		return 0, nil, err
	}
	return pin.h, func() { e.ws.releasePin(pin) }, nil
}

// scanResult is what one scan read from the host.
type scanResult struct {
	// err is a failure of the scan. The baseline scan fails the attach, and a
	// later scan ignores the failure and keeps the last state.
	err error

	// exists reports that the host still names the object where the guest
	// does.
	exists bool
	self   nameStat

	// snap describes a directory.
	snap dirSnapshot
}

// statSelf reads the state of the watched object through the guest path. The
// root has no name, so it reports itself as present with an empty state.
func (e *watchEntry) statSelf() (st nameStat, exists bool, err error) {
	parent, name, hasParent := e.selfNames()
	if !hasParent {
		if e.ws.single == "" {
			return nameStat{}, true, nil
		}
		// The root of a single-file workspace is the bound file.
		ent, err := e.ws.lookupPath(".")
		switch {
		case err == nil:
			return nameStatOf(ent.info), true, nil
		case errors.Is(err, fs.ErrNotExist):
			return nameStat{}, false, nil
		}
		return nameStat{}, false, err
	}
	ent, err := e.ws.lookupIn(parent, name)
	switch {
	case err == nil:
		if ent.virtual || ent.info.id != e.ino.id || ent.info.kind != e.ino.kind {
			return nameStat{}, false, nil
		}
		return nameStatOf(ent.info), true, nil
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, errNotDir):
		return nameStat{}, false, nil
	}
	return nameStat{}, false, err
}

// scanHost reads the watched object and, for a directory, its entries. It
// takes no lock that a guest mutation holds. The caller holds e.scanMu, which
// guards the previous snapshot that the scan reads.
func (e *watchEntry) scanHost() scanResult {
	var res scanResult
	st, exists, err := e.statSelf()
	if err != nil && e.suspectGone.Load() {
		// The backend lost its handle for a reason that means a removed
		// directory, and the lookup fails too. Take that as the removal.
		st, exists, err = nameStat{}, false, nil
	}
	if err != nil {
		res.err = err
		return res
	}
	res.exists, res.self = exists, st
	if !e.isDir || !exists {
		return res
	}
	dirRel := e.dirPath()
	dirInfo, names, infos, err := e.readEntries(dirRel)
	if err != nil {
		res.err = err
		return res
	}
	res.self = nameStatOf(dirInfo)
	res.snap = make(dirSnapshot, len(names))
	for i, name := range names {
		st := nameStatOf(infos[i])
		if prev, ok := e.snap[name]; ok && prev.sameFile(st) && !prev.contentChanged(st) {
			st.hidden, st.guest = prev.hidden, prev.guest
		} else {
			st.guest, st.hidden = e.visibleName(dirRel, name, infos[i])
		}
		res.snap[name] = st
	}
	return res
}

// maxListAttempts is how often a scan reads a directory again when a name
// vanishes between the listing and the stat.
const maxListAttempts = 3

// readEntries reads the state of the watched directory and of each of its
// entries through the handle of the directory. A name that the host cannot
// represent is left out. The guard keeps a directory rename away while the
// handle is open. Windows needs that, and the guard does nothing on Unix.
//
// The listing and the stat of each name are separate host calls. A rename
// between them makes the old name vanish after the listing listed it, and the
// new name is missing from the listing. A scan that took this state would
// report a deletion now and a creation later, and the pair would be lost. So a
// vanished name makes readEntries read the directory again.
func (e *watchEntry) readEntries(dirRel string) (dirInfo hostInfo, names []string, infos []hostInfo, err error) {
	unguard := e.ws.watchHandleGuard()
	defer unguard()
	h, release, err := e.dirHandle()
	if err != nil {
		return hostInfo{}, nil, nil, err
	}
	defer release()
	for range maxListAttempts {
		if dirInfo, err = e.ws.host.fstatDir(h); err != nil {
			return hostInfo{}, nil, nil, err
		}
		listed, err := e.ws.listNames(h, dirRel)
		if err != nil {
			return hostInfo{}, nil, nil, err
		}
		names = listed[:0]
		infos = make([]hostInfo, 0, len(listed))
		vanished := false
		for _, name := range listed {
			info, err := e.ws.host.lstatAt(h, name)
			if err != nil {
				vanished = vanished || errors.Is(err, fs.ErrNotExist)
				continue
			}
			names = append(names, name)
			infos = append(infos, info)
		}
		if !vanished {
			break
		}
	}
	return dirInfo, names, infos, nil
}

// visibleName decodes a host name and reports whether the guest sees it.
func (e *watchEntry) visibleName(dirRel, name string, info hostInfo) (guest string, hidden bool) {
	if info.kind == hostKindOther || (dirRel == "." && isReservedPath(name)) {
		return name, true
	}
	guest, ok := e.ws.hostVisibleName(dirRel, name, info)
	return guest, !ok
}

// rescan reads the host and sends the events for the changes since the last
// scan.
func (e *watchEntry) rescan() {
	e.scanMu.Lock()
	defer e.scanMu.Unlock()
	for range maxScanAttempts {
		if e.dead.Load() {
			return
		}
		e.mu.Lock()
		gen := e.gen
		e.mu.Unlock()
		res := e.scanHost()
		if e.commit(gen, res) {
			return
		}
	}
	e.scheduleRetry()
}

// scheduleRetry arranges one more rescan after scanRetryDelay.
func (e *watchEntry) scheduleRetry() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retry != nil || e.dead.Load() {
		return
	}
	e.retry = time.AfterFunc(scanRetryDelay, func() {
		e.mu.Lock()
		e.retry = nil
		e.mu.Unlock()
		e.rescan()
	})
}

type verdict uint8

const (
	verdictEmit verdict = iota
	verdictSuppress
	verdictDefer
)

// judgeChange decides whether a change of content or attributes that a scan
// found came from the guest. old is the state of the last scan, cur the state
// of this scan, and restat reads the state again. ino is the inode of the
// changed file, or nil when the VFS holds no inode for it. child is true for
// an entry of a watched directory, see diffEntry.
//
// The guest state is stable when no mutation runs and none finished between
// the first read of the generation and the stat. A mutation in progress gives
// verdictDefer, and the caller scans again later.
func judgeChange(ino *inode, old, cur nameStat, child bool, restat func() (nameStat, bool)) (verdict, changeKind, nameStat) {
	kindOf := func(o, c nameStat) changeKind {
		if ch, ok := diffEntry("", o, c, child); ok {
			return ch.kind
		}
		return 0
	}
	if ino == nil || cur.kind != hostKindRegular {
		return verdictEmit, kindOf(old, cur), cur
	}
	g := &ino.guest
	gen := g.gen.Load()
	if g.inflight.Load() > 0 {
		return verdictDefer, 0, cur
	}
	st := cur
	if again, ok := restat(); ok && again.sameFile(cur) {
		st = again
	}
	valid, gs := g.snapshot()
	if g.inflight.Load() > 0 || g.gen.Load() != gen {
		return verdictDefer, 0, cur
	}
	kind := kindOf(old, st)
	if kind == 0 {
		return verdictSuppress, 0, st
	}
	if !valid {
		return verdictEmit, kind, st
	}
	sameCtime := gs.ctime == st.ctime
	if kind == changeModify {
		if gs.mtime == st.mtime && gs.size == st.size {
			if sameCtime {
				return verdictSuppress, 0, st
			}
			return verdictEmit, changeAttrib, st
		}
		return verdictEmit, changeModify, st
	}
	if sameCtime {
		return verdictSuppress, 0, st
	}
	return verdictEmit, changeAttrib, st
}

// hostEvent is one notification for the watch set of an inode.
type hostEvent struct {
	target *vfs.Watches
	name   string
	mask   uint32
	cookie uint32
}

// hint tells the dentry cache which name a change touched.
type hint struct {
	guest string
	kind  changeKind
}

// dispatch collects the effects of one commit. The commit fills it under the
// locks, and apply runs it without them.
type dispatch struct {
	events   []hostEvent
	hints    []hint
	inval    []*inode
	selfEdit bool
	changed  bool
	gone     bool
	deferred bool
}

// commit compares res with the state of the last scan and sends the events.
// It returns false when a guest mutation invalidated the scan. The caller then
// scans again.
//
// The caller holds e.scanMu, which guards the last scan. commit holds
// filesystem.mu while it reads the guest state and decides, so no guest
// mutation through the VFS runs at that time. It does not hold e.mu across a
// host call: a guest mutation takes e.mu while it holds Workspace.mu.
func (e *watchEntry) commit(gen uint64, res scanResult) bool {
	if res.err != nil {
		return true
	}
	fs := e.ino.fs
	bg := context.Background()
	fs.lock()
	e.mu.Lock()
	if e.gen != gen || e.dead.Load() {
		e.mu.Unlock()
		fs.unlock(bg)
		return e.dead.Load()
	}
	touched := maps.Clone(e.touched)
	selfTouched := e.selfTouched
	e.mu.Unlock()

	var out dispatch
	e.review(fs, &res, touched, selfTouched, &out)

	e.mu.Lock()
	for n := range touched {
		delete(e.touched, n)
	}
	if selfTouched {
		e.selfTouched = false
	}
	e.mu.Unlock()
	e.cacheHintsLocked(&out)
	fs.unlock(bg)

	// The backend follows the new names before the guest hears of them, so
	// that a guest that reacts to a creation finds the new file watched.
	if !out.gone && e.isDir {
		if be := e.backendOrNil(); be != nil {
			be.synced(e, e.snap)
		}
	}
	e.apply(&out)
	return true
}

func (e *watchEntry) backendOrNil() watchBackend {
	e.hw.mu.Lock()
	defer e.hw.mu.Unlock()
	return e.hw.backend
}

// review diffs res against the last scan, judges each change, and stores res
// as the new last scan. The caller holds filesystem.mu and e.scanMu.
func (e *watchEntry) review(fs *filesystem, res *scanResult, touched map[string]struct{}, selfTouched bool, out *dispatch) {
	diff := diffSelf(e.self, res.self, res.exists)
	if diff.gone {
		out.gone = true
		return
	}
	if selfTouched {
		diff.kind = 0
	}
	if diff.kind != 0 {
		restat := func() (nameStat, bool) {
			st, exists, err := e.statSelf()
			return st, exists && err == nil
		}
		v, kind, st := judgeChange(e.ino, e.self, res.self, false, restat)
		switch v {
		case verdictDefer:
			out.deferred = true
			res.self = e.self
		case verdictEmit:
			res.self = st
			out.selfEdit = true
			mask := uint32(linux.IN_ATTRIB)
			if kind == changeModify {
				mask = linux.IN_MODIFY
				out.inval = append(out.inval, e.ino)
			}
			if e.isDir {
				mask |= linux.IN_ISDIR
			}
			out.events = append(out.events, hostEvent{target: &e.ino.watches, mask: mask})
		default:
			res.self = st
		}
	}
	e.self = res.self
	if !e.isDir {
		return
	}

	old := e.snap
	if len(touched) > 0 {
		old = adoptTouched(old, res.snap, touched)
	}
	next := res.snap
	var cookies map[uint32]uint32
	for _, ch := range diffDir(old, res.snap) {
		mask := ch.mask()
		cookie := uint32(0)
		if ch.pair != 0 {
			if cookies == nil {
				cookies = make(map[uint32]uint32)
			}
			if cookies[ch.pair] == 0 {
				cookies[ch.pair] = e.hw.nextCookie()
			}
			cookie = cookies[ch.pair]
		}
		if ch.kind == changeModify || ch.kind == changeAttrib {
			ino := fs.inodes[ch.cur.id]
			if ino != nil && ino.kind != ch.cur.kind {
				ino = nil
			}
			host := ch.host
			restat := func() (nameStat, bool) { return e.statChild(host) }
			v, kind, st := judgeChange(ino, ch.old, ch.cur, true, restat)
			if v == verdictDefer {
				next[host] = old[host]
				out.deferred = true
				continue
			}
			st.hidden, st.guest = ch.cur.hidden, ch.cur.guest
			next[host] = st
			if v == verdictSuppress {
				continue
			}
			ch.kind, ch.cur = kind, st
			mask = ch.mask()
			if kind == changeModify && ino != nil {
				out.inval = append(out.inval, ino)
			}
		}
		out.changed = true
		out.hints = append(out.hints, hint{guest: ch.cur.guest, kind: ch.kind})
		out.events = append(out.events, hostEvent{target: &e.ino.watches, name: ch.cur.guest, mask: mask, cookie: cookie})
	}
	e.snap = next
}

// adoptTouched returns old with the entries of the touched guest names taken
// from cur. The diff then reports nothing for those names, because a guest
// mutation made the change and the guest sent its own events. The result is a
// copy: the caller keeps old.
func adoptTouched(old, cur dirSnapshot, touched map[string]struct{}) dirSnapshot {
	adj := maps.Clone(old)
	if adj == nil {
		adj = make(dirSnapshot)
	}
	apply := func(n string, st nameStat) {
		if _, ok := touched[st.guest]; !ok {
			return
		}
		if c, ok := cur[n]; ok {
			adj[n] = c
		} else {
			delete(adj, n)
		}
	}
	for n, st := range old {
		apply(n, st)
	}
	for n, st := range cur {
		if _, ok := old[n]; !ok {
			apply(n, st)
		}
	}
	return adj
}

// statChild reads the state of the entry name of the watched directory.
func (e *watchEntry) statChild(name string) (nameStat, bool) {
	h, release, err := e.dirHandle()
	if err != nil {
		return nameStat{}, false
	}
	defer release()
	info, err := e.ws.host.lstatAt(h, name)
	if err != nil {
		return nameStat{}, false
	}
	return nameStatOf(info), true
}

// cacheHintsLocked drops the cached lookup results that the changes made
// stale. The caller holds filesystem.mu.
func (e *watchEntry) cacheHintsLocked(out *dispatch) {
	if e.d.dead || len(out.hints) == 0 {
		return
	}
	for _, h := range out.hints {
		if h.kind == changeCreate || h.kind == changeMovedTo {
			e.ino.negDel(h.guest)
		}
		if c := e.d.children[h.guest]; c != nil {
			c.inode.invalidateMeta()
		}
	}
	e.ino.invalidateMeta()
}

// apply runs the effects that commit collected. It holds no lock. The cache
// invalidation comes before the notifications, so that a guest that reacts to
// an event reads the new bytes.
func (e *watchEntry) apply(out *dispatch) {
	for _, ino := range out.inval {
		ino.invalidateMeta()
		ino.data.invalidateCleanChunks()
	}
	if out.selfEdit {
		e.ino.invalidateMeta()
	}
	if out.changed {
		e.ws.refreshNameCache(e.dirPath())
	}
	ctx := context.Background()
	for _, ev := range out.events {
		ev.target.Notify(ctx, ev.name, ev.mask, ev.cookie, vfs.InodeEvent, false)
	}
	e.hw.delivered.Add(uint64(len(out.events)))
	if out.gone {
		e.ino.invalidateMeta()
		// Only the call that ends the watch reports the deletion, so a removal
		// that the guest path already reported gives one event.
		if e.hw.remove(e) {
			e.ino.watches.HandleDeletion(ctx)
		}
		return
	}
	if out.deferred {
		e.scheduleRetry()
	}
}
