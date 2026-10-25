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
	"errors"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
)

const (
	chunkShift = chunkcache.ChunkShift
	chunkSize  = chunkcache.ChunkSize
)

type cacheChunk = chunkcache.Chunk

// fileData is the mapped-page cache of a regular file. The cache exists only
// while a mapping exists. The engine stays the source of truth for read and
// write system calls. Those calls write through to the engine and to the
// chunks that exist. A read first writes back the dirty chunks that it
// overlaps.
type fileData struct {
	chunkcache.Cache
	ino *inode
}

func (c *fileData) init(ino *inode) {
	c.ino = ino
	c.Init(c)
}

func (c *fileData) ChunkMemory() chunkcache.ChunkMemory { return c.ino.fs.vol.chunkMemory() }
func (c *fileData) FileSizeLocked() uint64              { return c.fileSize() }
func (c *fileData) TranslateError(err error) error      { return toLinuxErr(err) }
func (c *fileData) DropBackendLocked()                  {}

func (c *fileData) CanTranslateLocked(_ bool) error {
	if c.Chunks == nil {
		return linuxerr.ENODEV
	}
	return nil
}

func (c *fileData) PrepareAddMappingLocked() error {
	if c.Chunks == nil {
		c.Chunks = make(map[uint64]*cacheChunk)
		c.Active.Store(true)
	}
	return nil
}

func (c *fileData) ReadChunkAtLocked(dst []byte, off int64) error {
	_, err := c.ino.n.readAt(dst, off)
	return err
}

// fileSize returns the size of the file in bytes.
func (c *fileData) fileSize() uint64 {
	n := c.ino.n
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.size
}

// release drops the cache when the inode dies.
func (c *fileData) release(flush bool) error {
	var err error
	if flush {
		err = c.SyncData()
	}
	c.MapsMu.Lock()
	defer c.MapsMu.Unlock()
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	c.DropLocked()
	return err
}

// FlushLocked writes the dirty chunks that overlap [start, end) to the engine.
func (c *fileData) FlushLocked(start, end uint64) error {
	if len(c.Chunks) == 0 {
		return nil
	}
	size := c.fileSize()
	var errs []error
	wrote := false
	for idx, ch := range c.Chunks {
		base := idx << chunkShift
		if !ch.Dirty || base >= end || base+chunkSize <= start {
			continue
		}
		if base >= size {
			ch.Dirty = c.WritableMaps > 0
			continue
		}
		limit := min(size-base, chunkSize)
		if err := c.writeChunkLocked(ch, base, limit, &wrote); err != nil {
			errs = append(errs, err)
			continue
		}
		ch.Dirty = c.WritableMaps > 0
	}
	if wrote {
		c.ino.touchMCtime()
	}
	return errors.Join(errs...)
}

// writeChunkLocked writes the first limit bytes of ch, which sits at file
// offset base, page by page.
func (c *fileData) writeChunkLocked(ch *cacheChunk, base, limit uint64, wrote *bool) error {
	n := c.ino.n
	for off := uint64(0); off < limit; off += blockSize {
		page := ch.Buf[off:min(off+blockSize, limit)]
		if isZero(page) && holeAt(n, base+off) {
			continue
		}
		if _, err := n.writeAt(page, int64(base+off)); err != nil {
			return err
		}
		*wrote = true
	}
	return nil
}

// holeAt reports whether the block at file offset off has no data.
func holeAt(n *node, off uint64) bool {
	next, ok := n.seekData(off)
	return !ok || next >= off+blockSize
}

func isZero(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}

// writeThrough copies bytes that a system call wrote to the engine into the
// chunks that exist, so mapped pages observe them.
func (c *fileData) writeThrough(oldSize uint64, off int64, p []byte) {
	if !c.Active.Load() {
		return
	}
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	if uint64(off) > oldSize {
		c.ZeroLocked(oldSize, uint64(off))
	}
	c.CopyThroughLocked(off, p)
}

// truncated adjusts the cache after the engine changed the file size from old
// to size.
func (c *fileData) truncated(old, size uint64) {
	if !c.Active.Load() {
		return
	}
	if size >= old {
		c.DataMu.Lock()
		c.ZeroLocked(old, size)
		c.DataMu.Unlock()
		return
	}
	c.MapsMu.Lock()
	defer c.MapsMu.Unlock()
	c.DataMu.Lock()
	dropped := c.ShrinkLocked(size)
	c.DataMu.Unlock()
	c.InvalidateShrink(size, dropped)
}
