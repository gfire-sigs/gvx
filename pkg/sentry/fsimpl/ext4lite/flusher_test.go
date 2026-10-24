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
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// TestBackgroundFlushMakesChangesDurableWithoutFsync checks that a guest that
// never calls fsync still has its files on the host a few seconds later. The
// test clones the image after two background flushes.
func TestBackgroundFlushMakesChangesDurableWithoutFsync(t *testing.T) {
	flushIntervalNanos.Store(int64(2 * time.Millisecond))
	flushed := make(chan struct{}, 1024)
	hook := func() {
		select {
		case flushed <- struct{}{}:
		default:
		}
	}
	flushHook.Store(&hook)
	t.Cleanup(func() {
		flushIntervalNanos.Store(0)
		flushHook.Store(nil)
	})

	e := newEnv(t)
	e.mustMkdir("dir")
	data := pattern(7, 3*blockSize+17)
	e.writeFile("dir/file", data)
	fd := e.mustOpen("dir/open", linux.O_CREAT|linux.O_WRONLY)
	defer fd.DecRef(e.ctx)
	e.pwrite(fd, []byte("kept open"), 0)

	for len(flushed) > 0 {
		<-flushed
	}
	for range 2 {
		select {
		case <-flushed:
		case <-time.After(30 * time.Second):
			t.Fatal("no background flush ran")
		}
	}
	clone := cloneImage(t, e.path)

	r := openEnv(t, clone, VolumeOptions{}, vfs.MountOptions{})
	wantBytes(t, "file after the background flush", r.readFile("dir/file"), data)
	wantBytes(t, "open file after the background flush", r.readFile("dir/open"), []byte("kept open"))
}
