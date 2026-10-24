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
	"math"
	"os"
	"slices"
	"strings"
	"sync"
)

// This file implements the open-handle quiesce of GVXIP-001 section 3.
// NTFS refuses to rename a directory while a descendant file has an open
// handle. The registry knows every open regular-file handle. A directory
// rename closes the handles below the directory, renames the directory, and
// reopens the handles at the new paths. The logic is the same on every host,
// so tests exercise it everywhere. Only a host that sets LocksOpenDirMove
// creates a registry.
//
// The quiesce is safe for mapped pages. A mapped page lives in a chunk in
// Sentry memory, and the guest reads and writes the chunk without the host
// file. A chunk that the guest modified stays dirty until a write-back
// writes it. The write-back runs through the handle, which waits for the
// reopen. A closed handle therefore loses no mapped data, and the flush
// before the close only shortens the time that the data stays unsaved.

// handleOps is the host access that a quiesce needs. Workspace implements it
// with the real host backend. Tests implement it with a fake.
type handleOps interface {
	// flush writes back the mapped pages that depend on h. It records a
	// failure as the write-back error of the file, so the next fsync or
	// close reports it.
	flush(h *hostHandle)
	// identify returns the host identity of the open file f.
	identify(f *os.File) (hostID, error)
	// closeFile closes f.
	closeFile(f *os.File) error
	// reopen opens the file at the workspace-relative path rel with the
	// access mode flags. It never creates or truncates a file.
	reopen(rel string, flags int) (*os.File, error)
}

// errHandleChanged reports that a reopen found another host file at the path
// than the one that the handle held.
var errHandleChanged = errors.New("hostfs: the path names another host file after the directory rename")

// winHandleRegistry tracks open regular-file handles on Windows so directory
// renames can quiesce and reopen descendant handles atomically.
type winHandleRegistry struct {
	mu      sync.Mutex
	handles map[*hostHandle]struct{}
	nextSeq uint64
	ops     handleOps
}

func newWinHandleRegistry(ops handleOps) *winHandleRegistry {
	return &winHandleRegistry{handles: make(map[*hostHandle]struct{}), ops: ops}
}

// add registers h, which the caller opened at the workspace-relative path
// rel. A nil registry ignores the call.
func (r *winHandleRegistry) add(h *hostHandle, rel string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextSeq++
	h.reg = r
	h.path = rel
	h.seq = r.nextSeq
	r.handles[h] = struct{}{}
}

// remove forgets h. A nil registry ignores the call.
func (r *winHandleRegistry) remove(h *hostHandle) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.handles, h)
	r.mu.Unlock()
}

// detach forgets the handles that the path rel names. The name died, so a
// later rename of a parent directory has nothing to reopen. The handle keeps
// its open file and serves its file description until the guest closes it.
func (r *winHandleRegistry) detach(rel string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for h := range r.handles {
		if h.path == rel {
			delete(r.handles, h)
		}
	}
}

// moveFile gives the handles that the path oldRel names the path newRel. A
// rename of a file calls it. A rename of a directory moves its handles
// through quiesce instead.
func (r *winHandleRegistry) moveFile(oldRel, newRel string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for h := range r.handles {
		if h.path == oldRel {
			h.path = newRel
		}
	}
}

// pathOf returns the registered path of h.
func (r *winHandleRegistry) pathOf(h *hostHandle) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return h.path
}

// drop forgets h and records why it cannot serve the file description. The
// caller holds h.mu for writing.
func (r *winHandleRegistry) drop(h *hostHandle, cause error) error {
	h.err = fmt.Errorf("%w: %w", errHandleBroken, cause)
	r.remove(h)
	return h.err
}

// heldHandle is a handle that a quiesce closed.
type heldHandle struct {
	h    *hostHandle
	path string
	id   hostID
}

// quiescedTree is the set of handles below one directory. The quiesce closed
// their files and holds their locks until finish runs.
type quiescedTree struct {
	r      *winHandleRegistry
	oldRel string
	held   []heldHandle
}

// quiesce closes the host files of the handles below the directory oldRel
// and returns them with their locks held. The caller renames the directory
// and then calls finish exactly once. The caller holds Workspace.mu for
// writing, so no open adds a handle. A nil registry returns nil.
//
// The steps follow GVXIP-001 section 3.1, with one change in the order. The
// flush runs before the handle locks, because a flush takes fileData.dataMu
// and the lock order puts dataMu before hostHandle.mu. The flush is not a
// condition of correctness. See the comment at the top of this file.
//
// Two quiesces that run at the same time lock the handles in lexical path
// order, so they never wait for each other in a cycle.
func (r *winHandleRegistry) quiesce(oldRel string) *quiescedTree {
	if r == nil {
		return nil
	}
	prefix := oldRel + "/"
	r.mu.Lock()
	var matched []*hostHandle
	for h := range r.handles {
		if strings.HasPrefix(h.path, prefix) {
			matched = append(matched, h)
		}
	}
	slices.SortFunc(matched, func(a, b *hostHandle) int {
		if c := strings.Compare(a.path, b.path); c != 0 {
			return c
		}
		switch {
		case a.seq < b.seq:
			return -1
		case a.seq > b.seq:
			return 1
		}
		return 0
	})
	r.mu.Unlock()

	q := &quiescedTree{r: r, oldRel: oldRel}
	if len(matched) == 0 {
		return q
	}
	flushed := make(map[*fileData]struct{})
	for _, h := range matched {
		owner := h.owner.Load()
		if owner == nil {
			continue
		}
		if _, ok := flushed[owner]; !ok {
			flushed[owner] = struct{}{}
			r.ops.flush(h)
		}
	}
	for _, h := range matched {
		h.mu.Lock()
		// The last reference can drop, and a competing quiesce can move the
		// handle, between the match and the lock.
		path := r.pathOf(h)
		if h.dead || h.err != nil || !strings.HasPrefix(path, prefix) {
			h.mu.Unlock()
			continue
		}
		id, err := r.ops.identify(h.f)
		_ = r.ops.closeFile(h.f)
		if err != nil {
			_ = r.drop(h, err)
			h.mu.Unlock()
			continue
		}
		q.held = append(q.held, heldHandle{h: h, path: path, id: id})
	}
	return q
}

// finish reopens the handles that quiesce closed and releases their locks.
// When moved is true, the directory now has the path newRel. Otherwise the
// rename failed, and the handles reopen at the old path. A handle that does
// not reopen, or that finds another host file, becomes broken: it stays
// closed, and every later use returns an error that the guest sees as EIO.
// The result joins the reopen failures. A nil receiver does nothing.
func (q *quiescedTree) finish(moved bool, newRel string) error {
	if q == nil {
		return nil
	}
	target := q.oldRel
	if moved {
		target = newRel
	}
	var errs []error
	for _, e := range q.held {
		path := target + strings.TrimPrefix(e.path, q.oldRel)
		f, err := q.r.ops.reopen(path, e.h.flags)
		if err == nil {
			var id hostID
			if id, err = q.r.ops.identify(f); err == nil && id != e.id {
				err = errHandleChanged
			}
			if err != nil {
				_ = q.r.ops.closeFile(f)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, q.r.drop(e.h, err)))
			continue
		}
		e.h.f = f
		q.r.mu.Lock()
		e.h.path = path
		q.r.mu.Unlock()
	}
	for i := len(q.held) - 1; i >= 0; i-- {
		q.held[i].h.mu.Unlock()
	}
	q.held = nil
	return errors.Join(errs...)
}

// workspaceHandleOps implements handleOps on the host backend of a Workspace.
type workspaceHandleOps struct {
	w *Workspace
}

func (o workspaceHandleOps) flush(h *hostHandle) {
	d := h.owner.Load()
	if d == nil {
		return
	}
	if err := d.flushRange(0, math.MaxUint64); err != nil {
		d.noteWritebackErr(err)
	}
}

func (o workspaceHandleOps) identify(f *os.File) (hostID, error) {
	info, err := o.w.host.fstat(f)
	return info.id, err
}

func (o workspaceHandleOps) closeFile(f *os.File) error {
	return f.Close()
}

// reopen opens rel from the pinned workspace root with the original access
// mode. The host open uses the same share flags as every other open. The last
// component of an unnamed temporary file is a host name already, so it skips
// the name codec. The codec would escape the "~gvx~" prefix of the name.
func (o workspaceHandleOps) reopen(rel string, flags int) (*os.File, error) {
	parent, leaf := splitParent(rel)
	if !isEphemeralName(leaf) {
		hostRel, err := o.w.hostPath(rel)
		if err != nil {
			return nil, err
		}
		return o.w.host.open(hostRel, flags&accessModeMask, 0)
	}
	hostDir, err := o.w.hostPath(parent)
	if err != nil {
		return nil, err
	}
	return o.w.host.open(hostChild(hostDir, leaf), flags&accessModeMask, 0)
}
