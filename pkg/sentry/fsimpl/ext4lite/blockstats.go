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

package ext4lite

import (
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
)

// countedFile counts the host calls on the file of a volume as the requests of
// a block device. One ReadAt or WriteAt call is one request, one Sync call is
// one flush, and a Truncate call that shrinks the file is one discard of the
// removed tail. EnsureSize allocates space and moves no data, so it does not
// count.
//
// The engine reads and writes the host file only through this wrapper, so the
// counters see every block that the engine moves, in the unit of the host
// call and not in the unit of the guest system call.
type countedFile struct {
	hostFile
	stats *blockdev.Stats
}

// ReadAt implements io.ReaderAt.
func (c *countedFile) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return c.hostFile.ReadAt(p, off)
	}
	r := c.stats.Begin()
	n, err := c.hostFile.ReadAt(p, off)
	c.stats.End(blockdev.Read, r, int64(n))
	return n, err
}

// WriteAt implements io.WriterAt.
func (c *countedFile) WriteAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return c.hostFile.WriteAt(p, off)
	}
	r := c.stats.Begin()
	n, err := c.hostFile.WriteAt(p, off)
	c.stats.End(blockdev.Write, r, int64(n))
	return n, err
}

// Sync implements hostFile.
func (c *countedFile) Sync() error {
	r := c.stats.Begin()
	err := c.hostFile.Sync()
	c.stats.End(blockdev.Flush, r, 0)
	return err
}

// Truncate implements hostFile. A shrink releases the tail on the host volume,
// as a discard releases a range on a disk. A call that does not shrink the file
// moves no data and does not count.
func (c *countedFile) Truncate(size int64) error {
	before, err := c.hostFile.Size()
	if err != nil || size >= before {
		return c.hostFile.Truncate(size)
	}
	r := c.stats.Begin()
	err = c.hostFile.Truncate(size)
	released := int64(0)
	if err == nil {
		released = before - size
	}
	c.stats.End(blockdev.Discard, r, released)
	return err
}
