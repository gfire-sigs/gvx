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
	"io"
	"sync"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// stdioDeviceMajor is a character device major number from the range that
// Linux reserves for local and experimental use. The three stdio streams use
// the minor numbers 0, 1, and 2.
const stdioDeviceMajor = 240

// stdioDevice implements vfs.Device for one guest stdio stream.
//
// WHY: a guest reopens its standard streams through /dev/stdout and
// /proc/self/fd/N, and nginx does so for its log files. The magic link jumps
// to the dentry of the file description and opens it again. An anonymous
// dentry cannot be opened, so each stream lives behind a real character device
// node. A second open then creates a new file description on the same host
// reader or writer.
type stdioDevice struct {
	reader io.Reader
	writer io.Writer
	tty    *ttyState
	// mu serializes host I/O of every file description of the stream.
	mu *sync.Mutex
}

// Open implements vfs.Device.Open.
func (d stdioDevice) Open(ctx gvcontext.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &stdioFD{reader: d.reader, writer: d.writer, tty: d.tty, mu: d.mu}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		SpecialFile: d.tty != nil,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// openStdioFDs registers the stdio devices in vfsObj and returns the file
// descriptions for stdin, stdout, and stderr. The device nodes live on a
// private tmpfs that no mount namespace contains, so the guest sees the
// streams only through its descriptor table.
func openStdioFDs(ctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, in io.Reader, out, errw io.Writer, tty *ttyState) (fds [3]*vfs.FileDescription, err error) {
	devs := [3]stdioDevice{
		{reader: in},
		{writer: out},
		{writer: errw},
	}
	names := [3]string{"stdin", "stdout", "stderr"}
	flags := [3]uint32{linux.O_RDONLY, linux.O_WRONLY, linux.O_WRONLY}
	if tty != nil {
		errMu := tty.outMu
		if errw != out {
			errMu = new(sync.Mutex)
		}
		devs = [3]stdioDevice{
			{reader: in, writer: out, tty: tty, mu: tty.outMu},
			{reader: in, writer: out, tty: tty, mu: tty.outMu},
			{reader: in, writer: errw, tty: tty, mu: errMu},
		}
		flags = [3]uint32{linux.O_RDWR, linux.O_RDWR, linux.O_RDWR}
	}
	for i := range devs {
		if devs[i].mu == nil {
			devs[i].mu = new(sync.Mutex)
		}
		if err := vfsObj.RegisterDevice(vfs.CharDevice, stdioDeviceMajor, uint32(i), devs[i], &vfs.RegisterDeviceOptions{}); err != nil {
			return fds, fmt.Errorf("gvx: register the %s device: %w", names[i], err)
		}
	}

	fs, rootDentry, err := tmpfs.FilesystemType{}.GetFilesystem(ctx, vfsObj, creds, "", vfs.GetFilesystemOptions{})
	if err != nil {
		return fds, fmt.Errorf("gvx: create the stdio device filesystem: %w", err)
	}
	mnt := vfsObj.NewDisconnectedMount(fs, rootDentry, &vfs.MountOptions{})
	fs.DecRef(ctx)
	root := vfs.MakeVirtualDentry(mnt, rootDentry)
	defer root.DecRef(ctx)

	defer func() {
		if err == nil {
			return
		}
		for i, fd := range fds {
			if fd != nil {
				fd.DecRef(ctx)
				fds[i] = nil
			}
		}
	}()
	for i, name := range names {
		pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(name)}
		if err := vfsObj.MknodAt(ctx, creds, pop, &vfs.MknodOptions{
			Mode:     linux.S_IFCHR | 0o666,
			DevMajor: stdioDeviceMajor,
			DevMinor: uint32(i),
		}); err != nil {
			return fds, fmt.Errorf("gvx: create the %s device node: %w", name, err)
		}
		fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: flags[i]})
		if err != nil {
			return fds, fmt.Errorf("gvx: open the %s device node: %w", name, err)
		}
		fds[i] = fd
	}
	return fds, nil
}
