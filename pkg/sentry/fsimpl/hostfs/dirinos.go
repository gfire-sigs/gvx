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
	"sync"
)

// maxInoCacheDirs bounds the directories whose inode sets the cache holds.
const maxInoCacheDirs = 64

// dirInos is the set of inode numbers of one directory, as one listing showed
// it. The map is never changed after the cache stores it, so a reader can use
// it without a lock.
type dirInos struct {
	// rel is the guest path of the directory when the listing ran. A guest
	// mutation of the directory drops the entry by this path.
	rel string
	// until is the time up to which the listing is trusted.
	until int64
	// names maps an inode number to the guest name of the entry.
	names map[uint64]string
}

// inoCache holds the inode sets of directories, by directory identity. It
// answers the question "does the file with this inode number still live in the
// directory" without a listing for each question. A host editor that saves many
// files of one directory makes the guest ask once for each file, and a listing
// for each of them is quadratic.
//
// The cache has its own lock, which is a leaf. A guest mutation that adds or
// removes a name drops the entry of its directory. A host change cannot drop
// it, so an entry can be stale for cacheTTL. A stale entry makes an adoption
// decline or accept wrongly for that time at most, and a declined adoption
// tries again at the next stat after the entry expires.
type inoCache struct {
	mu   sync.Mutex
	dirs map[fileKey]*dirInos
}

// get returns the live entry of the directory, or nil.
func (c *inoCache) get(dir fileKey, now int64) *dirInos {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.dirs[dir]; e != nil && now < e.until {
		return e
	}
	return nil
}

// put stores the entry of the directory. A full cache drops every entry first.
func (c *inoCache) put(dir fileKey, e *dirInos) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, known := c.dirs[dir]
	if c.dirs == nil || (!known && len(c.dirs) >= maxInoCacheDirs) {
		c.dirs = make(map[fileKey]*dirInos)
	}
	c.dirs[dir] = e
}

// dropDir drops the entries of the guest directory rel.
func (c *inoCache) dropDir(rel string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.dirs {
		if e.rel == rel {
			delete(c.dirs, k)
		}
	}
}

// dropAll drops every entry. A rename of a directory changes the paths that
// the entries name.
func (c *inoCache) dropAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.dirs)
}

// dirInoNames returns the inode numbers of the directory rel with the guest
// names of their entries. pin is the pinned handle of the directory. A
// directory without an identity has no cache entry, so each call lists it.
func (w *Workspace) dirInoNames(pin *dirPin, rel string) (map[uint64]string, error) {
	now := w.nowNano()
	if !pin.key.isZero() {
		if e := w.inos.get(pin.key, now); e != nil {
			return e.names, nil
		}
	}
	entries, err := w.host.readDirAt(pin.h)
	if err != nil {
		return nil, err
	}
	names := make(map[uint64]string, len(entries))
	for _, e := range entries {
		if _, ok := names[e.ino]; !ok {
			names[e.ino] = w.codec.ToGuest(e.name)
		}
	}
	if !pin.key.isZero() {
		w.inos.put(pin.key, &dirInos{rel: rel, until: now + int64(cacheTTL), names: names})
	}
	return names, nil
}
