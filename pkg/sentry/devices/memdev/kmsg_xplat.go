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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

const kmsgDevMinor = 11

// RegisterKmsg registers /dev/kmsg in vfsObj. The device reads and writes the
// kernel log of the kernel of the opener. Documentation/ABI/testing/dev-kmsg of
// Linux describes the interface.
func RegisterKmsg(vfsObj *vfs.VirtualFilesystem) error {
	return vfsObj.RegisterDevice(vfs.CharDevice, linux.MEM_MAJOR, kmsgDevMinor, kmsgDevice{}, &vfs.RegisterDeviceOptions{
		GroupName: "mem",
		Pathname:  "kmsg",
		FilePerms: 0644,
	})
}

// kmsgDevice implements vfs.Device for /dev/kmsg.
type kmsgDevice struct{}

// Open implements vfs.Device.Open. Like devkmsg_open, it lets every opener
// write. A read needs CAP_SYSLOG when kernel.dmesg_restrict is 1. A reader
// starts at the oldest record.
func (kmsgDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return nil, linuxerr.ENODEV
	}
	creds := auth.CredentialsFromContext(ctx)
	klog := k.KernelLog()
	if opts.Flags&linux.O_ACCMODE != linux.O_WRONLY && klog.DmesgRestrict() && !kernel.CanReadKernelLog(creds, k) {
		return nil, linuxerr.EPERM
	}
	fd := &kmsgFD{log: klog, seq: klog.FirstSeq()}
	if err := fd.vfsfd.Init(fd, opts.Flags, creds, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile:       true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// kmsgFD implements vfs.FileDescriptionImpl for /dev/kmsg. Each descriptor has
// its own position in the log, the sequence number of the next record that a
// read returns.
type kmsgFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	log *kernel.KernelLog

	// limit is the rate limit of the writes through this descriptor.
	limit kernel.LogRateLimit

	mu sync.Mutex
	// seq is the position.
	seq uint64
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *kmsgFD) Release(context.Context) {}

// Readiness implements waiter.Waitable.Readiness. As devkmsg_poll does, it
// reports a record to read, and it adds an error when the ring dropped the
// record at the position. The device never reports a writable descriptor.
func (fd *kmsgFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	rec, ok := fd.log.Lookup(fd.seq)
	if !ok {
		return 0
	}
	ready := waiter.ReadableEvents
	if rec.Seq != fd.seq {
		ready |= waiter.EventErr | waiter.EventPri
	}
	return ready & mask
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *kmsgFD) EventRegister(e *waiter.Entry) error {
	return fd.log.EventRegister(e)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *kmsgFD) EventUnregister(e *waiter.Entry) {
	fd.log.EventUnregister(e)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *kmsgFD) Epollable() bool {
	return true
}

// Read implements vfs.FileDescriptionImpl.Read. One read returns one record in
// the format "prio,seq,usec,flag;text\n". It returns ErrWouldBlock when no
// record is left, so a blocking descriptor waits for the next record and a
// non-blocking descriptor gets EAGAIN. It returns EPIPE once when the ring
// dropped the record at the position, and moves to the oldest record. It
// returns EINVAL, without moving, when the buffer is smaller than the record.
func (fd *kmsgFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	rec, ok := fd.log.Lookup(fd.seq)
	if !ok {
		return 0, linuxerr.ErrWouldBlock
	}
	if rec.Seq != fd.seq {
		fd.seq = rec.Seq
		return 0, linuxerr.EPIPE
	}
	line := rec.AppendKmsg(nil)
	if int64(len(line)) > dst.NumBytes() {
		return 0, linuxerr.EINVAL
	}
	n, err := dst.CopyOut(ctx, line)
	if err != nil {
		return int64(n), err
	}
	fd.seq = rec.Seq + 1
	return int64(n), nil
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *kmsgFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *kmsgFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.ESPIPE
}

// Write implements vfs.FileDescriptionImpl.Write. See
// kernel.KernelLog.WriteDevkmsg for the prefix, the line splitting, the mode
// kernel.printk_devkmsg, and the rate limit.
func (fd *kmsgFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	n := src.NumBytes()
	if n > kernel.KernelLogRecordMax {
		return 0, linuxerr.EINVAL
	}
	buf := make([]byte, n)
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return 0, err
	}
	comm := "kernel"
	if t := kernel.TaskFromContext(ctx); t != nil {
		comm = t.Name()
	}
	if err := fd.log.WriteDevkmsg(&fd.limit, comm, buf); err != nil {
		return 0, err
	}
	return n, nil
}

// Seek implements vfs.FileDescriptionImpl.Seek. Only offset 0 is valid. SEEK_SET
// moves to the oldest record, SEEK_END moves after the newest record, and
// SEEK_DATA moves after the last record that syslog(2) cleared. Each call
// returns 0.
func (fd *kmsgFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.ESPIPE
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		fd.seq = fd.log.FirstSeq()
	case linux.SEEK_DATA:
		fd.seq = fd.log.ClearSeq()
	case linux.SEEK_END:
		fd.seq = fd.log.NextSeq()
	default:
		return 0, linuxerr.EINVAL
	}
	return 0, nil
}
