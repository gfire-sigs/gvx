// Copyright 2023 The gVisor Authors.
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
	"context"
	"fmt"
	"os"

	"z.gfire.dev/gvx/pkg/erofs"
	"z.gfire.dev/gvx/pkg/refs"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// afterLoad is called by stateify.
func (fs *filesystem) afterLoad(ctx context.Context) {
	fs.memoryFile = pgalloc.MemoryFileFromContext(ctx)
	fdmap := vfs.RestoreFilesystemFDMapFromContext(ctx)
	fd, ok := fdmap[fs.iopts.UniqueID]
	if !ok {
		panic(fmt.Sprintf("no image FD available for filesystem with unique ID %q, map: %#v", fs.iopts.UniqueID, fdmap))
	}
	// The image file owns the descriptor from here on. Delete the entry so
	// that the caller does not close it again, and so that a second
	// filesystem with the same unique ID fails instead of sharing one
	// descriptor between two os.File values.
	delete(fdmap, fs.iopts.UniqueID)
	imageFile := os.NewFile(uintptr(fd), "EROFS image file")
	newImage, err := erofs.OpenImage(imageFile)
	if err != nil {
		_ = imageFile.Close()
		panic(fmt.Sprintf("erofs.OpenImage failed: %v", err))
	}
	if got, want := newImage.SuperBlock(), fs.image.SuperBlock(); got != want {
		_ = imageFile.Close()
		panic(fmt.Sprintf("superblock mismatch detected on restore, got %+v, expected %+v", got, want))
	}
	// We need to update the image in place, as there are other pointers
	// pointing to this image as well.
	*fs.image = *newImage
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *dentry) loadParent(_ context.Context, parent *dentry) {
	d.parent.Store(parent)
}

// afterLoad is called by stateify.
func (d *dentry) afterLoad(context.Context) {
	if d.refs.Load() != -1 {
		refs.Register(d)
	}
}
