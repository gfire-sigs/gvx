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

package memdev

import (
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

const (
	kmsgDevMinor = 11

	// kmsgRecordMax is the longest record that a write may carry, as
	// PRINTKRB_RECORD_MAX of Linux.
	kmsgRecordMax = 1024
)

// RegisterKmsg registers /dev/kmsg in vfsObj. The Sentry has no kernel ring
// buffer, so the device never has a record to read.
func RegisterKmsg(vfsObj *vfs.VirtualFilesystem) error {
	return vfsObj.RegisterDevice(vfs.CharDevice, linux.MEM_MAJOR, kmsgDevMinor, kmsgDevice{}, &vfs.RegisterDeviceOptions{
		GroupName: "mem",
		Pathname:  "kmsg",
		FilePerms: 0644,
	})
}

// kmsgDevice implements vfs.Device for /dev/kmsg.
type kmsgDevice struct{}

// Open implements vfs.Device.Open.
func (kmsgDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &kmsgFD{}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile:       true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// kmsgFD implements vfs.FileDescriptionImpl for /dev/kmsg. A read returns
// EAGAIN on a non-blocking descriptor and blocks otherwise, as Linux does when
// the reader has seen every record. A write goes to the Sentry log.
type kmsgFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// queue holds the waiters for a record. No event ever fires.
	queue waiter.Queue
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *kmsgFD) Release(context.Context) {}

// Readiness implements waiter.Waitable.Readiness. The device never has a
// record to read, and a write never blocks.
func (fd *kmsgFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return mask & waiter.WritableEvents
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *kmsgFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *kmsgFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *kmsgFD) Epollable() bool {
	return true
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *kmsgFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, linuxerr.ErrWouldBlock
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *kmsgFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *kmsgFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// Write implements vfs.FileDescriptionImpl.Write. The text may start with a
// priority and facility in angle brackets, which the log line drops.
func (fd *kmsgFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	n := src.NumBytes()
	if n > kmsgRecordMax {
		return 0, linuxerr.EINVAL
	}
	buf := make([]byte, n)
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return 0, err
	}
	log.Infof("kmsg: %s", kmsgText(string(buf)))
	return n, nil
}

// kmsgText returns the message of a record without its priority prefix and its
// trailing newlines.
func kmsgText(record string) string {
	if rest, ok := strings.CutPrefix(record, "<"); ok {
		if prio, text, found := strings.Cut(rest, ">"); found && prio != "" && strings.Trim(prio, "0123456789") == "" {
			record = text
		}
	}
	return strings.TrimRight(record, "\n")
}

// Seek implements vfs.FileDescriptionImpl.Seek. Only offset 0 is valid. SEEK_SET
// and SEEK_DATA go to the first record, and SEEK_END goes past the last
// record. Without records, each call returns 0.
func (fd *kmsgFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.ESPIPE
	}
	switch whence {
	case linux.SEEK_SET, linux.SEEK_DATA, linux.SEEK_END:
		return 0, nil
	default:
		return 0, linuxerr.EINVAL
	}
}
