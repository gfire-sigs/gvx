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

package rungvx

import (
	"cmp"
	"os"
	"path"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/control"
)

const (
	defaultRPCFSWatchInterval = 100 * time.Millisecond
	defaultRPCFSMaxWatches    = 4096
	rpcfsWatchCookieBase      = uint32(1) << 31
)

type hostWatchStat struct {
	dev     uint64
	ino     uint64
	isDir   bool
	mode    os.FileMode
	size    int64
	mtimeNS int64
	ctimeNS int64
}

func hostWatchStatFromFileInfo(fi os.FileInfo) hostWatchStat {
	dev, ino, ctimeNS := hostWatchIdentity(fi)
	return hostWatchStat{
		dev:     dev,
		ino:     ino,
		isDir:   fi.IsDir(),
		mode:    fi.Mode(),
		size:    fi.Size(),
		mtimeNS: fi.ModTime().UnixNano(),
		ctimeNS: ctimeNS,
	}
}

func (s hostWatchStat) sameFile(o hostWatchStat) bool {
	if s.isDir != o.isDir {
		return false
	}
	if s.ino != 0 && o.ino != 0 {
		return s.dev == o.dev && s.ino == o.ino
	}
	return true
}

func (s hostWatchStat) contentChanged(o hostWatchStat) bool {
	return s.size != o.size || s.mtimeNS != o.mtimeNS
}

func (s hostWatchStat) attribChanged(o hostWatchStat) bool {
	return s.mode != o.mode || (s.ctimeNS != o.ctimeNS && s.mtimeNS == o.mtimeNS)
}

type hostWatchSnapshot struct {
	exists  bool
	isDir   bool
	self    hostWatchStat
	entries map[string]hostWatchStat
}

type hostWatchTarget struct {
	rel     string
	hostRel string

	// scanMu serializes snapshot reads and diff commits for this target.
	// Lock order: target.scanMu before watcher.mu.
	scanMu  sync.Mutex
	exists  bool
	isDir   bool
	self    hostWatchStat
	entries map[string]hostWatchStat

	// Protected by watcher.mu.
	inFlight int
	mutGen   uint64
}

// rpcfsHostWatcher polls only the host paths actively watched by guest inotify
// instances and emits control.RPCFSNotifyEvent notifications on changes.
type rpcfsHostWatcher struct {
	root       *os.Root
	singleFile bool
	leafName   string
	interval   time.Duration
	maxWatches int
	onNotify   func(control.RPCFSNotifyEvent)

	// opMu serializes Add and Remove calls so concurrent worker goroutines
	// cannot interleave a snapshot capture in Add with a concurrent Remove.
	// Lock order: opMu before mu.
	opMu    sync.Mutex
	mu      sync.Mutex
	watches map[string]*hostWatchTarget
	stop    chan struct{}
	closed  bool
	wg      sync.WaitGroup
	cookie  atomic.Uint32
}

func newRPCFSHostWatcher(root *os.Root, singleFile bool, leafName string, interval time.Duration, maxWatches int, onNotify func(control.RPCFSNotifyEvent)) *rpcfsHostWatcher {
	if interval <= 0 {
		interval = defaultRPCFSWatchInterval
	}
	if maxWatches <= 0 {
		maxWatches = defaultRPCFSMaxWatches
	}
	return &rpcfsHostWatcher{
		root:       root,
		singleFile: singleFile,
		leafName:   leafName,
		interval:   interval,
		maxWatches: maxWatches,
		onNotify:   onNotify,
		watches:    make(map[string]*hostWatchTarget),
	}
}

func (w *rpcfsHostWatcher) nextCookie() uint32 {
	return rpcfsWatchCookieBase | (w.cookie.Add(1) &^ rpcfsWatchCookieBase)
}

func (w *rpcfsHostWatcher) resolveHostRel(rel string) (string, int) {
	if !w.singleFile {
		return rel, 0
	}
	if rel != "." {
		return "", control.LinuxENOTDIR
	}
	return w.leafName, 0
}

func (w *rpcfsHostWatcher) captureSnapshot(hostRel string) (hostWatchSnapshot, error) {
	fi, err := w.root.Lstat(hostRel)
	if err != nil {
		if os.IsNotExist(err) {
			return hostWatchSnapshot{exists: false}, nil
		}
		return hostWatchSnapshot{}, err
	}
	snap := hostWatchSnapshot{
		exists: true,
		isDir:  fi.IsDir(),
		self:   hostWatchStatFromFileInfo(fi),
	}
	if w.singleFile || !fi.IsDir() {
		return snap, nil
	}
	f, err := w.root.Open(hostRel)
	if err != nil {
		if os.IsNotExist(err) {
			return hostWatchSnapshot{exists: false}, nil
		}
		return hostWatchSnapshot{}, err
	}
	des, err := f.ReadDir(-1)
	_ = f.Close()
	if err != nil {
		return hostWatchSnapshot{}, err
	}
	entries := make(map[string]hostWatchStat, len(des))
	for _, de := range des {
		name := de.Name()
		childRel := name
		if hostRel != "." {
			childRel = hostRel + "/" + name
		}
		cfi, err := w.root.Lstat(childRel)
		if err != nil {
			continue
		}
		entries[name] = hostWatchStatFromFileInfo(cfi)
	}
	snap.entries = entries
	return snap, nil
}

// Add registers a watch for rel and captures its baseline snapshot synchronously
// before returning 0, or returns a Linux errno on failure.
func (w *rpcfsHostWatcher) Add(rel string) int {
	hostRel, errno := w.resolveHostRel(rel)
	if errno != 0 {
		return errno
	}

	w.opMu.Lock()
	defer w.opMu.Unlock()

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return control.LinuxEIO
	}
	if _, exists := w.watches[rel]; exists {
		w.mu.Unlock()
		return 0
	}
	if len(w.watches) >= w.maxWatches {
		w.mu.Unlock()
		return control.LinuxENOSPC
	}
	w.mu.Unlock()

	snap, err := w.captureSnapshot(hostRel)
	if err != nil {
		return control.HostErrorToLinuxErrno(err)
	}
	if !snap.exists {
		return control.LinuxENOENT
	}

	target := &hostWatchTarget{
		rel:     rel,
		hostRel: hostRel,
		exists:  snap.exists,
		isDir:   snap.isDir,
		self:    snap.self,
		entries: snap.entries,
	}

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return control.LinuxEIO
	}
	if _, exists := w.watches[rel]; exists {
		w.mu.Unlock()
		return 0
	}
	if len(w.watches) >= w.maxWatches {
		w.mu.Unlock()
		return control.LinuxENOSPC
	}
	w.watches[rel] = target
	if w.stop == nil {
		stop := make(chan struct{})
		w.stop = stop
		w.wg.Add(1)
		go w.pollLoop(stop)
	}
	w.mu.Unlock()
	return 0
}

// Remove unregisters the watch for rel and stops the poll goroutine when no
// watches remain.
func (w *rpcfsHostWatcher) Remove(rel string) {
	w.opMu.Lock()
	defer w.opMu.Unlock()

	w.mu.Lock()
	delete(w.watches, rel)
	if len(w.watches) == 0 && w.stop != nil {
		close(w.stop)
		w.stop = nil
	}
	w.mu.Unlock()
}

// Close stops polling and waits for any active poll goroutine to return.
func (w *rpcfsHostWatcher) Close() {
	w.mu.Lock()
	w.closed = true
	if w.stop != nil {
		close(w.stop)
		w.stop = nil
	}
	clear(w.watches)
	w.mu.Unlock()
	w.wg.Wait()
}

func affectedWatchPaths(singleFile bool, rels []string) []string {
	if singleFile {
		return []string{"."}
	}
	seen := make(map[string]struct{}, len(rels)*2)
	out := make([]string, 0, len(rels)*2)
	add := func(p string) {
		if p == "" {
			p = "."
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, r := range rels {
		if r == "" {
			continue
		}
		add(r)
		if r != "." {
			dir := path.Dir(r)
			if dir == "" || dir == "/" {
				dir = "."
			}
			add(dir)
		}
	}
	return out
}

// BeginMutation marks guest-initiated mutations in flight for echo suppression.
func (w *rpcfsHostWatcher) BeginMutation(rels ...string) []*hostWatchTarget {
	paths := affectedWatchPaths(w.singleFile, rels)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || len(w.watches) == 0 {
		return nil
	}
	var affected []*hostWatchTarget
	for _, p := range paths {
		if t, ok := w.watches[p]; ok {
			t.inFlight++
			t.mutGen++
			affected = append(affected, t)
		}
	}
	return affected
}

// EndMutation refreshes baseline snapshots after a guest-initiated mutation so
// subsequent polls do not re-emit events that the guest VFS already delivered.
func (w *rpcfsHostWatcher) EndMutation(targets []*hostWatchTarget) {
	if len(targets) == 0 {
		return
	}
	for _, t := range targets {
		t.scanMu.Lock()
		snap, err := w.captureSnapshot(t.hostRel)
		if err == nil {
			t.exists = snap.exists
			t.isDir = snap.isDir
			t.self = snap.self
			t.entries = snap.entries
		}
		t.scanMu.Unlock()

		w.mu.Lock()
		if t.inFlight > 0 {
			t.inFlight--
		}
		t.mutGen++
		w.mu.Unlock()
	}
}

func (w *rpcfsHostWatcher) pollLoop(stop <-chan struct{}) {
	defer w.wg.Done()
	timer := time.NewTimer(w.interval)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
		}
		start := time.Now()
		w.scanAll(stop)
		delay := max(w.interval, time.Since(start)*2)
		timer.Reset(delay)
	}
}

func (w *rpcfsHostWatcher) scanAll(stop <-chan struct{}) {
	w.mu.Lock()
	list := make([]*hostWatchTarget, 0, len(w.watches))
	for _, t := range w.watches {
		list = append(list, t)
	}
	w.mu.Unlock()

	for _, t := range list {
		if stop != nil {
			select {
			case <-stop:
				return
			default:
			}
		}
		w.scanTarget(t)
	}
}

func (w *rpcfsHostWatcher) scanTarget(t *hostWatchTarget) {
	t.scanMu.Lock()
	w.mu.Lock()
	if w.closed || t.inFlight > 0 || w.watches[t.rel] != t {
		w.mu.Unlock()
		t.scanMu.Unlock()
		return
	}
	genBefore := t.mutGen
	w.mu.Unlock()

	snap, err := w.captureSnapshot(t.hostRel)
	if err != nil {
		t.scanMu.Unlock()
		return
	}

	w.mu.Lock()
	if w.closed || t.inFlight > 0 || t.mutGen != genBefore || w.watches[t.rel] != t {
		w.mu.Unlock()
		t.scanMu.Unlock()
		return
	}
	w.mu.Unlock()

	events := w.diffTarget(t, snap)
	t.exists = snap.exists
	t.isDir = snap.isDir
	t.self = snap.self
	t.entries = snap.entries
	t.scanMu.Unlock()

	if w.onNotify == nil {
		return
	}
	for _, ev := range events {
		w.onNotify(ev)
	}
}

func (w *rpcfsHostWatcher) diffTarget(t *hostWatchTarget, cur hostWatchSnapshot) []control.RPCFSNotifyEvent {
	if !t.exists {
		if !cur.exists {
			return nil
		}
		// Recreated after prior deletion: notify watchers of fresh content.
		mask := control.LinuxInModify
		if cur.isDir {
			mask = control.LinuxInAttrib | control.LinuxInIsDir
		}
		return []control.RPCFSNotifyEvent{{Path: t.rel, Mask: mask}}
	}
	if !cur.exists {
		return []control.RPCFSNotifyEvent{{Path: t.rel, Mask: control.LinuxInDeleteSelf}}
	}
	if !t.isDir {
		if !t.self.sameFile(cur.self) || t.self.contentChanged(cur.self) {
			return []control.RPCFSNotifyEvent{{Path: t.rel, Mask: control.LinuxInModify}}
		}
		if t.self.attribChanged(cur.self) {
			return []control.RPCFSNotifyEvent{{Path: t.rel, Mask: control.LinuxInAttrib}}
		}
		return nil
	}
	return w.diffDir(t.rel, t.entries, cur.entries)
}

func (w *rpcfsHostWatcher) diffDir(rel string, oldEntries, curEntries map[string]hostWatchStat) []control.RPCFSNotifyEvent {
	names := make([]string, 0, len(oldEntries)+len(curEntries))
	for n := range oldEntries {
		names = append(names, n)
	}
	for n := range curEntries {
		if _, ok := oldEntries[n]; !ok {
			names = append(names, n)
		}
	}
	slices.Sort(names)

	type goneEntry struct {
		name     string
		st       hostWatchStat
		replaced bool
	}
	type cameEntry struct {
		name     string
		st       hostWatchStat
		replaced bool
	}
	var gone []goneEntry
	var came []cameEntry
	var edits []control.RPCFSNotifyEvent

	for _, n := range names {
		o, inOld := oldEntries[n]
		c, inCur := curEntries[n]
		switch {
		case inOld && !inCur:
			gone = append(gone, goneEntry{name: n, st: o})
		case !inOld && inCur:
			came = append(came, cameEntry{name: n, st: c})
		case inOld && inCur && !o.sameFile(c):
			gone = append(gone, goneEntry{name: n, st: o, replaced: true})
			came = append(came, cameEntry{name: n, st: c, replaced: true})
		case inOld && inCur:
			if c.isDir {
				if o.attribChanged(c) {
					edits = append(edits, control.RPCFSNotifyEvent{
						Path: rel, Name: n, Mask: control.LinuxInAttrib | control.LinuxInIsDir,
					})
				}
			} else if o.contentChanged(c) {
				edits = append(edits, control.RPCFSNotifyEvent{
					Path: rel, Name: n, Mask: control.LinuxInModify,
				})
			} else if o.attribChanged(c) {
				edits = append(edits, control.RPCFSNotifyEvent{
					Path: rel, Name: n, Mask: control.LinuxInAttrib,
				})
			}
		}
	}

	fromCookie := make([]uint32, len(gone))
	toCookie := make([]uint32, len(came))
	replacedByMove := make(map[string]bool)
	for ai, a := range came {
		if a.st.ino == 0 {
			continue
		}
		for gi, g := range gone {
			if fromCookie[gi] != 0 || g.name == a.name || !g.st.sameFile(a.st) || g.st.size != a.st.size || g.st.mtimeNS != a.st.mtimeNS {
				continue
			}
			cookie := w.nextCookie()
			fromCookie[gi] = cookie
			toCookie[ai] = cookie
			if a.replaced {
				replacedByMove[a.name] = true
			}
			break
		}
	}

	out := make([]control.RPCFSNotifyEvent, 0, len(gone)+len(came)+len(edits))
	for gi, g := range gone {
		if fromCookie[gi] == 0 {
			continue
		}
		dirBit := uint32(0)
		if g.st.isDir {
			dirBit = control.LinuxInIsDir
		}
		out = append(out, control.RPCFSNotifyEvent{
			Path: rel, Name: g.name, Mask: control.LinuxInMovedFrom | dirBit, Cookie: fromCookie[gi],
		})
		for ai, a := range came {
			if toCookie[ai] == fromCookie[gi] {
				out = append(out, control.RPCFSNotifyEvent{
					Path: rel, Name: a.name, Mask: control.LinuxInMovedTo | dirBit, Cookie: toCookie[ai],
				})
				break
			}
		}
	}
	for gi, g := range gone {
		if fromCookie[gi] != 0 || (g.replaced && replacedByMove[g.name]) {
			continue
		}
		mask := control.LinuxInDelete
		if g.st.isDir {
			mask |= control.LinuxInIsDir
		}
		out = append(out, control.RPCFSNotifyEvent{Path: rel, Name: g.name, Mask: mask})
	}
	for ai, a := range came {
		if toCookie[ai] != 0 {
			continue
		}
		mask := control.LinuxInCreate
		if a.st.isDir {
			mask |= control.LinuxInIsDir
		}
		out = append(out, control.RPCFSNotifyEvent{Path: rel, Name: a.name, Mask: mask})
	}
	out = append(out, edits...)
	return out
}

func sortDirEntriesByName(des []os.DirEntry) {
	slices.SortFunc(des, func(a, b os.DirEntry) int {
		return cmp.Compare(a.Name(), b.Name())
	})
}
