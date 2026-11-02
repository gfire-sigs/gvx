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
	"os"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// setSource records the dentry that AddMapping can open a handle through.
func (c *fileData) setSource(d *dentry) {
	c.DataMu.Lock()
	c.src = d
	c.DataMu.Unlock()
}

// AddMapping implements memmap.Mappable.AddMapping. It shadows the method of
// the embedded cache.
//
// WHY: The overlay filesystem keeps the Mappable of a layer file after the
// first mmap. For every later mmap it calls AddMapping and skips
// ConfigureMMap, so nothing reserves a handle. The last unmap of the file
// drops the handle, so a later mapping would have no backend and each page
// fault of the program would fail. A program that starts twice from a hostfs
// layer, such as a container binary, then ends with SIGBUS or EFAULT. This
// method opens a handle when none exists.
func (c *fileData) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	if err := c.ensureHandle(writable); err != nil {
		return err
	}
	return c.Cache.AddMapping(ctx, ms, ar, offset, writable)
}

// ensureHandle reserves a handle for the AddMapping call when the file data
// has no handle with the access that the mapping needs. A ConfigureMMap call
// that ran before AddMapping has already reserved one, and this method then
// does nothing.
//
// The method opens the handle before it takes DataMu, because the lock order
// puts Workspace.mu first. A race with another mapping is safe: reserveHandle
// keeps the better handle.
func (c *fileData) ensureHandle(writable bool) error {
	c.DataMu.Lock()
	haveWritable := c.mhWritable || (c.pending != nil && c.pendingWritable)
	needed := (c.mh == nil && c.pending == nil) || (writable && !haveWritable)
	src := c.src
	c.DataMu.Unlock()
	if !needed || src == nil {
		return nil
	}
	flags := os.O_RDONLY
	if writable {
		flags = os.O_RDWR
	}
	h, err := src.openHost(flags)
	if err != nil {
		return translateHostError(err)
	}
	defer func() { _ = h.decRef() }()
	// The path of the dentry can name another file now, for example after a
	// host process replaced the file. A mapping of another file would show
	// wrong bytes.
	info, err := h.fstat(c.ino.fs.ws.host)
	if err != nil {
		return translateHostError(err)
	}
	if info.id != c.ino.id {
		return linuxerr.ENODEV
	}
	c.reserveHandle(h, writable)
	return nil
}
