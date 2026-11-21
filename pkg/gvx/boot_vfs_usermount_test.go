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

package gvx

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// TestGuestCannotMountHostResources proves that mount(2) of the guest cannot
// create a file system that takes a host resource as its source. The guest
// controls the source path and the option data of mount(2). VFS.NewFilesystem
// without InternalMount is the path of that system call.
func TestGuestCannotMountHostResources(t *testing.T) {
	mf := newTestMemoryFile(t, "user-mount-test")
	clock := &ktime.SyntheticClock{}
	clock.Store(ktime.FromNanoseconds(1_700_000_000_000_000_000))
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	sctx := newTestSentryContext(t, mf, clock, creds)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(sctx); err != nil {
		t.Fatalf("vfs.Init: %v", err)
	}
	defer vfsObj.Release(sctx)
	if err := registerKernelVFS(vfsObj, nil); err != nil {
		t.Fatalf("registerKernelVFS: %v", err)
	}

	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "secret.txt"), []byte("host-secret"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// hostFile stands for a descriptor that the host process holds, such as
	// a volume image. Its content is not an EROFS image.
	hostFile, err := os.CreateTemp(t.TempDir(), "host-descriptor-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = hostFile.Close() }()

	userMount := func(source, fsName, data string) error {
		fs, root, err := vfsObj.NewFilesystem(sctx, creds, source, fsName, &vfs.MountOptions{
			GetFilesystemOptions: vfs.GetFilesystemOptions{Data: data},
		})
		if err == nil {
			root.DecRef(sctx)
			fs.DecRef(sctx)
		}
		return err
	}

	// A file system without a host source stays available to the guest.
	if err := userMount("", "tmpfs", ""); err != nil {
		t.Fatalf("guest mount of tmpfs: %v", err)
	}

	if err := userMount(hostDir, hostfs.Name, ""); !linuxerr.Equals(linuxerr.ENODEV, err) {
		t.Errorf("guest mount of hostfs on %s = %v, want ENODEV", hostDir, err)
	}
	if err := userMount("", "erofs", fmt.Sprintf("ifd=%d", hostFile.Fd())); !linuxerr.Equals(linuxerr.ENODEV, err) {
		t.Errorf("guest mount of erofs with ifd = %v, want ENODEV", err)
	}
	// The refused erofs mount must not adopt and close the host descriptor.
	if _, err := hostFile.Stat(); err != nil {
		t.Errorf("host descriptor after the erofs mount attempt: %v", err)
	}

	// The hostfs driver opens no host path itself. Without the workspace
	// that the Sentry opened, the mount fails, also for an internal caller.
	fs, root, err := hostfs.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, hostDir, vfs.GetFilesystemOptions{InternalMount: true})
	if err == nil {
		root.DecRef(sctx)
		fs.DecRef(sctx)
	}
	if !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("hostfs mount by source path = %v, want EINVAL", err)
	}
}
