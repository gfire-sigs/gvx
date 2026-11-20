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

package virtgpu

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

// syncFileFD is a sync_file: a descriptor that becomes readable when its fence
// signals. It answers no ioctl (SYNC_IOC_MERGE and SYNC_IOC_FILE_INFO are day
// two), and it cannot be read or written.
type syncFileFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	f *fence
}

var _ vfs.FileDescriptionImpl = (*syncFileFD)(nil)

// newSyncFile returns a new sync_file for f with one reference.
func newSyncFile(ctx context.Context, vfsObj *vfs.VirtualFilesystem, f *fence) (*vfs.FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("sync_file")
	defer vd.DecRef(ctx)

	sf := &syncFileFD{f: f}
	if err := sf.vfsfd.Init(sf, linux.O_RDONLY, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		return nil, err
	}
	return &sf.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release. The fence stays in its
// pending list until it signals.
func (sf *syncFileFD) Release(context.Context) {}

// Readiness implements waiter.Waitable.Readiness.
func (sf *syncFileFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	if sf.f.signaled.Load() {
		return mask & waiter.ReadableEvents
	}
	return 0
}

// EventRegister implements waiter.Waitable.EventRegister.
func (sf *syncFileFD) EventRegister(e *waiter.Entry) error {
	sf.f.queue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (sf *syncFileFD) EventUnregister(e *waiter.Entry) {
	sf.f.queue.EventUnregister(e)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (sf *syncFileFD) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (sf *syncFileFD) Ioctl(context.Context, usermem.IO, uintptr, arch.SyscallArguments) (uintptr, error) {
	return 0, linuxerr.ENOTTY
}
