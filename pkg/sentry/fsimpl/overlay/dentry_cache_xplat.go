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

package overlay

import (
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

var _ vfs.FilesystemImplSaveRestoreExtension = (*filesystem)(nil)

// maxUnusedDentries is the number of dentries without references that a
// filesystem keeps for later lookups.
//
// WHY: overlay destroyed a dentry when its last reference dropped. Every path
// resolution then looked up each component again in each layer. A stat(2) of
// a file two directories below the root took about four times as long as on
// a plain tmpfs, and a merged directory cost more for each lower layer. The
// gofer, kernfs, and erofs filesystems keep unused dentries in the same way.
const maxUnusedDentries = 4096

// dentryCacheEntry links a dentry into a dentryCache.
type dentryCacheEntry struct {
	prev, next *dentry
	cached     bool
}

// dentryCache is a least recently used list of dentries that have no
// references. The most recently used dentry is at the head.
type dentryCache struct {
	head, tail *dentry
	len        int
	// closed is true after the filesystem started its release. A dentry that
	// drops its last reference then is destroyed at once.
	closed bool
}

// pushFront inserts d at the head. d must not be in c.
func (c *dentryCache) pushFront(d *dentry) {
	e := &d.unusedEntry
	e.prev, e.next, e.cached = nil, c.head, true
	if c.head != nil {
		c.head.unusedEntry.prev = d
	} else {
		c.tail = d
	}
	c.head = d
	c.len++
}

// remove takes d out of c. It does nothing when d is not in c.
func (c *dentryCache) remove(d *dentry) {
	e := &d.unusedEntry
	if !e.cached {
		return
	}
	if e.prev != nil {
		e.prev.unusedEntry.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.unusedEntry.prev = e.prev
	} else {
		c.tail = e.prev
	}
	*e = dentryCacheEntry{}
	c.len--
}

// cacheOrDestroyLocked keeps d, which has no references, at the head of the
// unused list, and destroys the least recently used dentries that do not fit.
// It destroys d at once when d is deleted, when d is the root, or when the
// filesystem is in release. The root has no references only after its mount
// is gone.
//
// Preconditions:
//   - fs.renameMu must be locked for writing.
//   - d.refs == 0.
func (fs *filesystem) cacheOrDestroyLocked(ctx context.Context, d *dentry) {
	if !d.vfsd.IsDead() && d.watches.Size() > 0 {
		fs.unused.remove(d)
		return
	}
	if d.vfsd.IsDead() || d.parent.Load() == nil || fs.unused.closed {
		d.destroyLocked(ctx)
		return
	}
	fs.unused.remove(d)
	fs.unused.pushFront(d)
	for fs.unused.len > maxUnusedDentries {
		victim := fs.unused.tail
		fs.unused.remove(victim)
		// A lookup can take a reference on a dentry in the list. Such a
		// dentry returns to the list when it loses that reference.
		if victim.refs.Load() == 0 && (victim.vfsd.IsDead() || victim.watches.Size() == 0) {
			victim.destroyLocked(ctx)
		}
	}
}

// evictUnusedDentries destroys every dentry in the unused list and stops
// further caching. The list holds references on the parents of its dentries,
// and through them on the layers, so the filesystem must empty it at release.
func (fs *filesystem) evictUnusedDentries(ctx context.Context) {
	fs.drainUnusedDentries(ctx, true)
}

func (fs *filesystem) drainUnusedDentries(ctx context.Context, closeCache bool) {
	renameIdx := fs.renameLockIndex()
	fs.renameMu.NestedLock(renameIdx)
	defer fs.renameMu.NestedUnlock(renameIdx)
	wasClosed := fs.unused.closed
	fs.unused.closed = true
	for fs.unused.tail != nil {
		victim := fs.unused.tail
		fs.unused.remove(victim)
		if victim.refs.Load() == 0 && (closeCache || victim.vfsd.IsDead() || victim.watches.Size() == 0) {
			victim.destroyLocked(ctx)
		}
	}
	if !closeCache {
		fs.unused.closed = wasClosed
	}
}

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context, _ vfs.PrepareSaveOptions) error {
	fs.drainUnusedDentries(ctx, false)
	return nil
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(context.Context) {}

// CompleteRestore implements vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(context.Context, vfs.CompleteRestoreOptions) error {
	return nil
}
