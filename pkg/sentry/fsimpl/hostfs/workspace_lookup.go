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
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// exactNameIn reports whether the host stores the entry leaf of the guest
// directory parent under exactly that name. On a case-insensitive volume the
// host resolves "A" to a file stored as "a". Guest code expects case-sensitive
// names, so hostfs compares the requested name with the stored directory
// entry. A non-nil pin is the pinned handle of the directory parent.
func (w *Workspace) exactNameIn(parent, leaf string, pin *dirPin) (bool, error) {
	if !w.host.caseInsensitive() {
		return true, nil
	}
	for attempt := range 2 {
		snap, fresh, err := w.snapshotDir(parent, pin, attempt == 1)
		if err != nil {
			return false, err
		}
		w.nameMu.Lock()
		_, ok := snap.names[leaf]
		w.nameMu.Unlock()
		if ok || fresh {
			return ok, nil
		}
		// A cached snapshot may predate an external creation: re-read once.
	}
	return false, nil
}

// snapshotDir returns the listing snapshot of the guest directory parent. The
// snapshot stays valid for cacheTTL without a host call, and a stat of the
// directory proves it afterwards. A non-nil pin is the pinned handle of the
// directory. forceRead skips the cache. The second result reports that the
// call read the directory from the host.
func (w *Workspace) snapshotDir(parent string, pin *dirPin, forceRead bool) (*dirNames, bool, error) {
	now := w.nowNano()
	w.nameMu.Lock()
	cached := w.nameCache[parent]
	if !forceRead && cached != nil && now < cached.until {
		w.nameMu.Unlock()
		return cached, false, nil
	}
	w.nameMu.Unlock()
	pinfo, err := w.dirInfo(parent, pin)
	if err != nil {
		return nil, false, err
	}
	if !forceRead {
		w.nameMu.Lock()
		cached = w.nameCache[parent]
		if cached != nil && cached.id == pinfo.id && cached.mtime == pinfo.mtime.UnixNano() {
			cached.until = now + int64(cacheTTL)
			w.nameMu.Unlock()
			return cached, false, nil
		}
		w.nameMu.Unlock()
	}
	var entries []hostDirEntry
	if pin != nil {
		entries, err = w.host.readDirAt(pin.h)
	} else {
		var hostDir string
		if hostDir, err = w.hostPath(parent); err != nil {
			return nil, false, err
		}
		entries, err = w.host.readDir(hostDir)
	}
	if err != nil {
		return nil, false, err
	}
	snap := &dirNames{id: pinfo.id, mtime: pinfo.mtime.UnixNano(), until: now + int64(cacheTTL), names: make(map[string]struct{}, len(entries))}
	for _, e := range entries {
		snap.names[e.name] = struct{}{}
	}
	w.nameMu.Lock()
	if len(w.nameCache) >= maxNameCacheDirs {
		w.nameCache = make(map[string]*dirNames)
	}
	w.nameCache[parent] = snap
	w.nameMu.Unlock()
	return snap, true, nil
}

// dirInfo reads the metadata of the guest directory rel. It uses the pin when
// one is given and a path walk otherwise.
func (w *Workspace) dirInfo(rel string, pin *dirPin) (hostInfo, error) {
	if pin != nil {
		return w.host.fstatDir(pin.h)
	}
	hostDir, err := w.hostPath(rel)
	if err != nil {
		return hostInfo{}, err
	}
	return w.host.lstat(hostDir)
}

// needsExactCheck reports whether the backend resolves a name that differs in
// case from the stored name and leaves the comparison to hostfs.
func (w *Workspace) needsExactCheck() bool {
	return w.host.caseInsensitive() && !w.host.caseVerified()
}

// tracksDirNames reports whether the listing snapshots need updates when the
// guest mutates a directory.
func (w *Workspace) tracksDirNames() bool {
	return w.stateful || w.needsExactCheck()
}

// addDirNameLocked records that the host directory dir now holds the entry
// hostName for the guest name name. It updates the snapshot of dir in place, so
// the next lookup does not list dir again. A directory without a snapshot stays
// without one. Callers hold w.mu for writing.
func (w *Workspace) addDirNameLocked(dir, name, hostName string) {
	w.updateDirName(dir, name, hostName, true)
}

// removeDirNameLocked records that the host directory dir no longer holds the
// entry hostName. Callers hold w.mu for writing.
func (w *Workspace) removeDirNameLocked(dir, name, hostName string) {
	w.updateDirName(dir, name, hostName, false)
}

func (w *Workspace) updateDirName(dir, name, hostName string, present bool) {
	w.watchNoteName(dir, name)
	w.inos.dropDir(dir)
	if !w.tracksDirNames() {
		return
	}
	w.nameMu.Lock()
	cached := w.nameCache[dir]
	if cached == nil {
		w.nameMu.Unlock()
		return
	}
	if present {
		cached.names[hostName] = struct{}{}
	} else {
		delete(cached.names, hostName)
	}
	cached.aux = nil
	w.nameMu.Unlock()

	// The mutation changed the modification time of the directory. Stamp the
	// snapshot with the new time, or the next stat would reject it.
	pin := w.holdPin(dir)
	info, err := w.dirInfo(dir, pin)
	if pin != nil {
		w.releasePin(pin)
	}
	now := w.nowNano()
	w.nameMu.Lock()
	defer w.nameMu.Unlock()
	if w.nameCache[dir] != cached {
		return
	}
	if err != nil {
		delete(w.nameCache, dir)
		return
	}
	cached.id = info.id
	cached.mtime = info.mtime.UnixNano()
	cached.until = now + int64(cacheTTL)
}

// dropDirNamesLocked drops the snapshots of the directory rel and of every
// directory below it. A directory rename or removal changes whole subtrees,
// which the in-place updates cannot express. Callers hold w.mu for writing.
func (w *Workspace) dropDirNamesLocked(rel string) {
	w.inos.dropAll()
	if !w.tracksDirNames() {
		return
	}
	prefix := rel + "/"
	w.nameMu.Lock()
	defer w.nameMu.Unlock()
	for k := range w.nameCache {
		if rel == "." || k == rel || strings.HasPrefix(k, prefix) {
			delete(w.nameCache, k)
		}
	}
}

func defaultPerm(info hostInfo) uint32 {
	return info.perm & 0o7777
}

// effectiveAttr layers the .gvx_meta record over the host metadata. The file
// type always comes from the host so a stale record cannot change the type.
func (w *Workspace) effectiveAttr(rel string, info hostInfo) POSIXAttr {
	var typ uint32
	switch info.kind {
	case hostKindDir:
		typ = linux.S_IFDIR
	default:
		typ = linux.S_IFREG
	}
	key := w.keyOf(rel, info)
	if r := w.recOf(rel, info); r != nil {
		m := r.attr
		a := POSIXAttr{
			Mode:   typ | m.Mode&0o7777,
			UID:    m.UID,
			GID:    m.GID,
			Mtime:  m.Mtime,
			Ctime:  m.Ctime,
			Xattrs: m.Xattrs,
		}
		if st := placeholderType(info, m); st != 0 {
			a.Mode, a.Rdev = st|m.Mode&0o7777, m.Rdev
		}
		if t := w.dirTimes[key]; t > 0 {
			a.Mtime = max(a.Mtime, t)
			a.Ctime = max(a.Ctime, t)
		}
		return a
	}
	a := POSIXAttr{Mode: typ | defaultPerm(info)}
	if t := w.dirTimes[key]; t > 0 {
		a.Mtime = t
		a.Ctime = t
	}
	return a
}

// touchDirLocked records now as the modification and change time of dir when a
// virtual symlink changes inside it without a host directory mutation. Callers
// hold w.mu for writing.
func (w *Workspace) touchDirLocked(dir string, now int64) {
	pin, err := w.acquirePin(dir)
	if err != nil {
		return
	}
	defer w.releasePin(pin)
	key := w.dirKeyOf(pin, dir)
	if r := w.meta.get(key); r != nil {
		next := *r
		next.attr.Mtime = now
		next.attr.Ctime = now
		w.meta.put(key, &next)
		return
	}
	w.dirTimes[key] = now
}

// lookupLocked resolves rel to its effective state without following links. It
// reads the entry through the pinned handle of its directory. Callers hold
// w.mu.
func (w *Workspace) lookupLocked(rel string) (entry, error) {
	e, _, err := w.lookupProbeLocked(rel)
	return e, err
}

// lookupProbeLocked is lookupLocked that also returns where the host holds the
// entry, or the name that a new entry at rel would get. Callers hold w.mu.
func (w *Workspace) lookupProbeLocked(rel string) (entry, hostProbe, error) {
	if w.closed {
		return entry{}, hostProbe{}, os.ErrClosed
	}
	if isReservedPath(rel) || (w.single != "" && rel != ".") {
		return entry{}, hostProbe{}, fs.ErrNotExist
	}
	if k, r := w.virtualAtLocked(rel); r != nil {
		return virtualEntry(k, r), hostProbe{}, nil
	}
	if rel == "." {
		info, err := w.host.lstat(rel)
		if err != nil {
			return entry{}, hostProbe{}, err
		}
		e, err := w.entryFromInfo(rel, info)
		return e, hostProbe{found: true, info: info}, err
	}
	p, err := w.locateLocked(rel)
	if err != nil {
		return entry{}, hostProbe{}, err
	}
	if !p.found || p.hidden {
		return entry{}, p, p.missingError(rel)
	}
	e, err := w.entryFromInfo(rel, p.info)
	return e, p, err
}

// entryFromInfo builds the effective state of rel from its host metadata.
// Callers hold w.mu.
func (w *Workspace) entryFromInfo(rel string, info hostInfo) (entry, error) {
	switch info.kind {
	case hostKindDir, hostKindRegular:
		attr := w.effectiveAttr(rel, info)
		if specialFileType(attr.Mode) != 0 {
			info.kind, info.size, info.blocks = hostKindSpecial, 0, 0
		}
		return entry{attr: attr, info: info, key: w.keyOf(rel, info)}, nil
	case hostKindSymlink:
		hostRel, err := w.hostPath(rel)
		if err != nil {
			return entry{}, err
		}
		target, err := w.host.readlink(hostRel)
		if err != nil {
			return entry{}, err
		}
		if validateSymlinkTarget(rel, target) != nil {
			return entry{}, ErrPathTraversal
		}
		return entry{attr: POSIXAttr{Mode: linux.S_IFLNK | 0o777, Symlink: target}, info: info}, nil
	default:
		return entry{}, ErrPathTraversal
	}
}

// nameMismatch builds the error for a name that exists on the host only under
// another case.
func nameMismatch(rel string) error {
	return fmt.Errorf("hostfs: lookup %q: %w: %w", rel, errNameMismatch, fs.ErrNotExist)
}

func virtualEntry(k recKey, r *rec) entry {
	m := r.attr
	ts := time.Unix(0, m.Ctime)
	return entry{
		attr:    m,
		virtual: true,
		key:     k,
		info: hostInfo{
			kind:  hostKindSymlink,
			size:  int64(len(m.Symlink)),
			nlink: 1,
			perm:  0o777,
			atime: time.Unix(0, m.Atime),
			mtime: time.Unix(0, m.Mtime),
			ctime: ts,
			btime: ts,
		},
	}
}

func (w *Workspace) lookup(rel string) (entry, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lookupLocked(rel)
}

// Readlink returns the symlink target for relPath from .gvx_meta or the host OS.
func (w *Workspace) Readlink(relPath string) (string, error) {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return "", err
	}
	e, err := w.lookup(cleanRel)
	if err != nil {
		return "", err
	}
	if !e.isSymlink() {
		return "", fs.ErrInvalid
	}
	return e.attr.Symlink, nil
}

// Stat returns the combined host FileInfo and virtual POSIXAttr for relPath.
func (w *Workspace) Stat(relPath string) (POSIXAttr, int64, error) {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return POSIXAttr{}, 0, err
	}
	e, err := w.lookup(cleanRel)
	if err != nil {
		return POSIXAttr{}, 0, err
	}
	return e.attr, e.info.size, nil
}

// dirListing is one directory entry with its type and the host inode number
// when the host layer reports it.
type dirListing struct {
	name    string
	kind    hostKind
	ino     uint64
	virtual bool
	// leaf is the stored host name. It is empty for a virtual symlink.
	leaf string
	// special is the file type of a socket, FIFO, or device record, or zero.
	special uint32
}

// listDir returns the visible children of the directory at rel, host entries
// and virtual symlinks, sorted by name.
func (w *Workspace) listDir(rel string) ([]dirListing, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out, _, err := w.listDirLocked(rel)
	return out, err
}

// listDirLocked is listDir for a caller that holds w.mu. It also returns the
// stored names of the host clutter files that the listing hides. The listing
// teaches the alternate-name table the stored name of every entry whose guest
// name differs from it.
func (w *Workspace) listDirLocked(rel string) ([]dirListing, []string, error) {
	if w.closed {
		return nil, nil, os.ErrClosed
	}
	hostDir, err := w.hostPath(rel)
	if err != nil {
		return nil, nil, err
	}
	pin, err := w.acquirePin(rel)
	if err != nil {
		return nil, nil, err
	}
	defer w.releasePin(pin)
	dirKey := w.dirKeyOf(pin, rel)
	entries, err := w.host.readDirAt(pin.h)
	if err != nil {
		return nil, nil, err
	}
	var clutter []string
	byName := make(map[string]dirListing, len(entries))
	for _, e := range entries {
		l, isClutter, keep := w.classifyDirEntryLocked(pin, rel, hostDir, dirKey, e)
		if isClutter {
			clutter = append(clutter, e.name)
			continue
		}
		if !keep {
			continue
		}
		if old, dup := byName[l.name]; dup && old.leaf == l.name {
			// Two host names show as one guest name. The plain name wins.
			continue
		}
		if l.name != e.name {
			w.setAlt(rel, l.name, e.name)
		}
		byName[l.name] = l
	}
	for _, name := range w.meta.kidsOf(dirKey) {
		byName[name] = dirListing{name: name, kind: hostKindSymlink, virtual: true}
	}
	out := make([]dirListing, 0, len(byName))
	for _, l := range byName {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, clutter, nil
}

// classifyDirEntryLocked evaluates one raw host directory entry and returns its
// guest listing, whether it is removable clutter, and whether it is visible.
func (w *Workspace) classifyDirEntryLocked(pin *dirPin, rel, hostDir string, dirKey recKey, e hostDirEntry) (listing dirListing, isClutter, keep bool) {
	if rel == "." && isReservedPath(e.name) {
		return dirListing{}, false, false
	}
	if e.kind == hostKindOther || w.hiddenByName(e.name) {
		// An internal file has no owner while the guest sees an empty
		// directory, so the removal of the directory unlinks it.
		return dirListing{}, e.kind == hostKindRegular && isEphemeralName(e.name), false
	}
	if w.clutter.candidate(e.name) {
		info := hostInfo{kind: e.kind}
		if e.kind == hostKindRegular && (w.clutter.needsContent(e.name) || !w.pathKeys) {
			fi, err := w.host.lstatAt(pin.h, e.name)
			if err != nil {
				return dirListing{}, false, false
			}
			info = fi
		}
		if w.isClutterLocked(rel, e.name, info) {
			return dirListing{}, true, false
		}
	}
	guest := w.listName(rel, e.name)
	if e.kind == hostKindSymlink {
		full := joinRelPath(rel, guest)
		if w.meta.has(dirKey.withName(guest)) {
			return dirListing{}, false, false
		}
		target, err := w.host.readlink(hostChild(hostDir, e.name))
		if err != nil || validateSymlinkTarget(full, target) != nil {
			return dirListing{}, false, false
		}
	}
	l := dirListing{name: guest, kind: e.kind, ino: e.ino, leaf: e.name}
	if e.kind == hostKindRegular {
		l.special = w.placeholderOfLocked(pin, rel, guest, e)
	}
	return l, false, true
}

// ListEntries returns the sorted workspace-relative paths of all files,
// directories, and .gvx_meta symlinks inside the workspace (excluding .gvx_meta).
func (w *Workspace) ListEntries() ([]string, error) {
	var out []string
	var walk func(rel string) error
	walk = func(rel string) error {
		children, err := w.listDir(rel)
		if err != nil {
			return err
		}
		for _, c := range children {
			full := joinRelPath(rel, c.name)
			out = append(out, full)
			if c.kind == hostKindDir {
				if err := walk(full); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk("."); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// DirChild describes a direct child entry of a workspace directory.
type DirChild struct {
	Name string
	Attr POSIXAttr
	Size int64
}

// ReadDirChildren returns the sorted direct children of the directory at relPath.
func (w *Workspace) ReadDirChildren(relPath string) ([]DirChild, error) {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return nil, err
	}
	children, err := w.listDir(cleanRel)
	if err != nil {
		return nil, err
	}
	out := make([]DirChild, 0, len(children))
	for _, c := range children {
		e, err := w.lookup(joinRelPath(cleanRel, c.name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		out = append(out, DirChild{Name: c.name, Attr: e.attr, Size: e.info.size})
	}
	return out, nil
}

// placeholderOfLocked returns the file type of a socket, FIFO, or device
// record that the host entry e of the directory rel, shown as guest, stands for, or zero. A
// listing carries no identity, so on a volume with identities only an entry
// whose inode number a special record names gets a stat. A table without
// special records costs nothing. Callers hold w.mu.
func (w *Workspace) placeholderOfLocked(pin *dirPin, rel, guest string, e hostDirEntry) uint32 {
	if r := w.meta.get(recKey{kind: kindPath, path: joinRelPath(rel, guest)}); r != nil {
		return specialFileType(r.attr.Mode)
	}
	if w.pathKeys || e.ino == 0 || !w.meta.hasSpecialIno(e.ino) {
		return 0
	}
	info, err := w.host.lstatAt(pin.h, e.name)
	if err != nil || !hasIdentity(info) {
		return 0
	}
	if r := w.meta.get(w.keyOf("", info)); r != nil {
		return placeholderType(info, r.attr)
	}
	return 0
}
