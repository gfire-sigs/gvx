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
	"io/fs"
	"runtime"
)

// flushNeedsWrite reports a host that flushes a file handle only when the
// handle has write access. FlushFileBuffers on Windows is one.
var flushNeedsWrite = runtime.GOOS == "windows"

// This file implements the durability contract of GVXIP-001 section 6. An
// ordinary metadata mutation reaches .gvx_meta after the coalesce window
// (defaultCoalesceWindow). A guest that calls fsync, fdatasync, or sync, or
// that writes through a descriptor with O_SYNC or O_DSYNC, must not wait for
// that window. Those calls flush in this order, and each step reports its own
// failure:
//
//  1. the dirty mapped pages of the file (fileData.syncData),
//  2. the host file (hostHandle.sync),
//  3. the directory entry of the file (Workspace.syncDir of the parent), and
//  4. the metadata table (Workspace.Sync), which flushes the workspace
//     directory after its own atomic rename.
//
// A write with O_SYNC or O_DSYNC flushes the directory entry only on the first
// such write of a file description. The entry cannot change through the
// description in between, and a directory flush for every database commit
// would double the cost of the write.

// persist makes the file of fd durable. It runs the four steps above, and it
// flushes the directory entry when withDir is true. The result joins the
// failures of all steps.
func (fd *regularFD) persist(withDir bool) error {
	d := fd.dentry
	var errs []error
	if err := d.inode.data.syncData(); err != nil {
		errs = append(errs, err)
	}
	if err := fd.h.sync(); err != nil {
		errs = append(errs, err)
	}
	if withDir {
		if err := d.syncParentDir(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := d.fs.ws.Sync(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// syncWrite makes a write through an O_SYNC or O_DSYNC description durable. The
// write covers the file range [start, end). It flushes the directory entry on
// the first call of the description only.
func (fd *regularFD) syncWrite(start, end int64) error {
	if err := fd.dentry.inode.data.flushRange(uint64(start), uint64(end)); err != nil {
		return err
	}
	withDir := fd.dirSynced.CompareAndSwap(false, true)
	return fd.persist(withDir)
}

// syncParentDir flushes the host directory that holds the name of d. A
// dentry without a name has no directory entry. A parent that a host process
// removed has no entry left to flush, so that case is not a failure.
func (d *dentry) syncParentDir() error {
	rel := d.path()
	if rel == "." || d.isDead() {
		return nil
	}
	parent, _ := splitParent(rel)
	if err := d.fs.ws.syncDir(parent); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// syncHost flushes the host file behind the mapped pages. It does nothing
// while no mapping holds a handle.
func (c *fileData) syncHost() error {
	c.dataMu.Lock()
	h := c.mh
	if h != nil {
		h.incRef()
	}
	c.dataMu.Unlock()
	if h == nil {
		return nil
	}
	err := h.sync()
	_ = h.decRef()
	return err
}

// syncFile writes back the mapped pages of the inode and flushes the host file
// behind them. Filesystem.Sync calls it for each inode.
func (i *inode) syncFile() error {
	return errors.Join(i.data.syncData(), i.data.syncHost())
}
