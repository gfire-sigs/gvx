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

import "sync"

// dirLinkCache holds the counted link count of a directory and the host
// modification time of the directory that the count matches.
type dirLinkCache struct {
	mu    sync.Mutex
	mtime int64
	links uint32
}

// dirLinks returns the link count that stat reports for the directory d with
// the host entry e. Linux counts "." and the ".." of each subdirectory, so a
// directory has 2 links plus one for each subdirectory. NTFS reports one link
// for every directory, so on such a host hostfs counts the subdirectories
// that the guest sees. The count stays cached until the modification time of
// the host directory changes, because the host changes that time when an
// entry is created, removed, or renamed.
func (d *dentry) dirLinks(e entry, hostLinks uint32) uint32 {
	if hostCountsDirLinks || d.inode.unlinked.Load() {
		return hostLinks
	}
	c := &d.inode.dirLinks
	mtime := e.info.mtime.UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.links != 0 && c.mtime == mtime {
		return c.links
	}
	entries, err := d.fs.ws.listDir(d.path())
	if err != nil {
		return hostLinks
	}
	links := uint32(2)
	for _, l := range entries {
		if l.kind == hostKindDir && !l.virtual {
			links++
		}
	}
	c.mtime, c.links = mtime, links
	return links
}
