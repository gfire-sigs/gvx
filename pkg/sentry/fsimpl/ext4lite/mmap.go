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
	"bytes"
	"errors"
	"io"

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
//
// Lock order: the inode write mutex wmu comes first, then the cache MapsMu,
// then the cache DataMu, then the node mutex n.mu. A write-back runs with
// DataMu held, so it never takes wmu. The callers that write back take wmu
// before they call into the cache. A memory-manager call that drops a mapping
// takes MapsMu and DataMu without wmu, so the write-back checks the size under
// n.mu for every page it writes.
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

// release drops the cache when the inode dies. A flush takes the write mutex
// first, as every other write-back does.
func (c *fileData) release(flush bool) error {
	var err error
	if flush {
		c.ino.wmu.Lock()
		err = c.SyncData()
		c.ino.wmu.Unlock()
	}
	c.MapsMu.Lock()
	defer c.MapsMu.Unlock()
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	c.DropLocked()
	return err
}

// flushMapped writes back the dirty pages of the mapping that overlap [start,
// end). It takes the write mutex first, so a truncate, a punch, or an
// allocation cannot run between the write-back and its size check. The caller
// holds no lock of the inode.
func (i *inode) flushMapped(start, end uint64) error {
	if !i.data.Active.Load() {
		return nil
	}
	i.wmu.Lock()
	defer i.wmu.Unlock()
	return i.data.FlushRange(start, end)
}

// FlushLocked writes the dirty chunks that overlap [start, end) to the engine.
// The caller holds DataMu.
func (c *fileData) FlushLocked(start, end uint64) error {
	if len(c.Chunks) == 0 {
		return nil
	}
	var errs []error
	wrote := false
	for idx, ch := range c.Chunks {
		base := idx << chunkShift
		if !ch.Dirty || base >= end || base+chunkSize <= start {
			continue
		}
		if err := c.writeChunkLocked(ch, base, &wrote); err != nil {
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

// writeChunkLocked writes the pages of ch whose bytes differ from the file. Its
// base is the file offset of the chunk. A page that matches the file costs no
// write, and the times of the file stay as they are for it.
func (c *fileData) writeChunkLocked(ch *cacheChunk, base uint64, wrote *bool) error {
	n := c.ino.n
	var cur [blockSize]byte
	for off := uint64(0); off < chunkSize; off += blockSize {
		pos := base + off
		page := ch.Buf[off : off+blockSize]
		k, err := n.readAt(cur[:], int64(pos))
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if k == 0 || bytes.Equal(cur[:k], page[:k]) {
			continue
		}
		w, err := n.writeBackAt(page[:k], int64(pos))
		if err != nil {
			return err
		}
		if w > 0 {
			*wrote = true
		}
	}
	return nil
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

func isZero(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}
