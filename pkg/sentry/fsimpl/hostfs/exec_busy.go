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
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// This file keeps a running program from changing under its own feet. The
// kernel calls vfs.FileDescription.DenyWriteAccess on the file that a process
// executes. The call finds the vfs.WriteCount of the inode through
// dentry.WriteCount. While the count is positive, every path that could change
// the content of the file fails with ETXTBSY, as Linux does and as tmpfs does:
//
//   - an open that asks for write access, which includes O_TRUNC,
//   - truncate(2), which needs write access like such an open,
//   - a writable shared memory mapping.
//
// Hard links share one inode and so share one count. A host process is not
// subject to the count.

// WriteCount implements vfs.WriteCounter.WriteCount.
func (d *dentry) WriteCount() *vfs.WriteCount {
	return &d.inode.writeCount
}

// checkWritable fails with ETXTBSY while a process executes the file.
func (i *inode) checkWritable() error {
	return i.writeCount.CheckWrite()
}

// checkMapping fails with ETXTBSY for a writable shared mapping of a file that
// a process executes. A private mapping never writes the file, so it passes.
func (i *inode) checkMapping(opts *memmap.MMapOpts) error {
	if opts.Private || !opts.Perms.Write {
		return nil
	}
	return i.writeCount.CheckWrite()
}
