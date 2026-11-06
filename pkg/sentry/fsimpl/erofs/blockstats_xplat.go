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

package erofs

import (
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
)

// The image file of an EROFS file system is a disk of the sandbox when the
// mount passes InternalFilesystemOptions.BlockStats. The counters then show the
// file data that the file system takes from the image. The image sits behind
// the page cache of the host, so a page counts once, in full, at its first
// read or at the first mapping that needs it, as a cache fill does on Linux.
// A read of a page that an earlier read or mapping touched counts nothing. A
// hole has no data in the image, so it counts nothing. The metadata of the
// image (inodes, directory blocks, and extended attributes) comes through the
// memory mapping of the image and is not counted.

// newBlockStats prepares the set of touched pages of the image.
func (fs *filesystem) newBlockStats() {
	if fs.iopts.BlockStats != nil {
		fs.touched = blockdev.NewFirstTouch(uint64(fs.image.Blocks()) * uint64(fs.image.BlockSize()))
	}
}

// beginRead starts a read request for the n bytes at the image offset off. It
// returns the bytes of the range that no earlier read touched. It starts no
// request, and it returns 0, when the mount has no counters or the range is in
// the cache already.
func (fs *filesystem) beginRead(off, n uint64) (uint64, blockdev.Request) {
	if fs.touched == nil {
		return 0, blockdev.Request{}
	}
	fresh := fs.touched.Claim(off, n)
	if fresh == 0 {
		return 0, blockdev.Request{}
	}
	return fresh, fs.iopts.BlockStats.Begin()
}

// endRead completes the request r that beginRead returned with the fresh bytes.
func (fs *filesystem) endRead(r blockdev.Request, fresh uint64) {
	fs.iopts.BlockStats.End(blockdev.Read, r, int64(fresh))
}

// countMappedRead counts the pages that a guest mapping of the n bytes at the
// image offset off takes from the image for the first time. The mapping reads
// nothing at this point, so the request has no duration and no lock is held.
func (fs *filesystem) countMappedRead(off, n uint64) {
	if fs.touched == nil {
		return
	}
	if fresh := fs.touched.Claim(off, n); fresh > 0 {
		fs.iopts.BlockStats.Add(blockdev.Read, int64(fresh))
	}
}
