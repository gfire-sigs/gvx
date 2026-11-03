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

// dirLinkCache holds the counted link count of a directory, with the host
// modification time and the metadata sequence of the inode that the count
// matches.
type dirLinkCache struct {
	mu    sync.Mutex
	mtime int64
	seq   uint64
	links uint32
}

// dirLinks returns the link count that stat reports for the directory d with
// the host entry e. Linux counts "." and the ".." of each subdirectory, so a
// directory has 2 links plus one for each subdirectory. NTFS reports one link
// for every directory, so on such a host hostfs counts the subdirectories
// that the guest sees.
//
// The count stays cached while two values stay the same. The metadata
// sequence of the inode advances at every guest change of the directory. The
// host modification time shows a change by a host process. The time alone is
// not enough: NTFS takes it from the system clock, which advances in steps of
// up to 16 ms, so two guest changes can leave the same time.
func (d *dentry) dirLinks(e entry, hostLinks uint32) uint32 {
	if !d.fs.ws.countsDirLinks || d.inode.unlinked.Load() {
		return hostLinks
	}
	c := &d.inode.dirLinks
	mtime := e.info.mtime.UnixNano()
	seq := d.inode.beginMeta()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.links != 0 && c.mtime == mtime && c.seq == seq {
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
	c.mtime, c.seq, c.links = mtime, seq, links
	return links
}
