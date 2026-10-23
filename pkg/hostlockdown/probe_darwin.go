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

//go:build darwin

package hostlockdown

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Self-probes run inside the locked process. Each probe changes no host state
// when the lockdown works. They exist so that Status reports enforcement that
// the kernel demonstrated, not enforcement that Apply merely requested.

// unlistedProbePaths are existing, world-readable host files that no profile
// rule allows.
var unlistedProbePaths = []string{"/private/etc/passwd", "/usr/bin/true", "/bin/sh"}

// descriptorProbe holds a pipe that Apply opens before the Seatbelt profile
// takes effect. Reading it afterwards proves that held descriptors stay usable.
type descriptorProbe struct {
	r, w   int
	closed bool
}

const descriptorProbeByte = 0x5a

func newDescriptorProbe() (*descriptorProbe, error) {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		return nil, fmt.Errorf("hostlockdown: create descriptor probe pipe: %w", err)
	}
	p := &descriptorProbe{r: fds[0], w: fds[1]}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
	}
	if _, err := unix.Write(p.w, []byte{descriptorProbeByte}); err != nil {
		p.close()
		return nil, fmt.Errorf("hostlockdown: seed descriptor probe pipe: %w", err)
	}
	return p, nil
}

func (p *descriptorProbe) close() {
	if p.closed {
		return
	}
	p.closed = true
	_ = unix.Close(p.r)
	_ = unix.Close(p.w)
}

// verify reads the seeded byte through the pre-opened descriptor.
func (p *descriptorProbe) verify() error {
	if p.closed {
		return errors.New("hostlockdown: descriptor probe already closed")
	}
	defer p.close()
	var buf [1]byte
	n, err := unix.Read(p.r, buf[:])
	if err != nil {
		return fmt.Errorf("hostlockdown: read pre-opened descriptor after lockdown: %w", err)
	}
	if n != 1 || buf[0] != descriptorProbeByte {
		return fmt.Errorf("hostlockdown: pre-opened descriptor returned %d bytes (%#x), want 1 byte %#x", n, buf[0], descriptorProbeByte)
	}
	return nil
}

func isDenied(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

// probeSubprocessBlocked starts /usr/bin/true. The lockdown works when the
// kernel rejects the fork.
func probeSubprocessBlocked() error {
	proc, err := os.StartProcess("/usr/bin/true", []string{"true"}, &os.ProcAttr{})
	if err == nil {
		_, _ = proc.Wait()
		return errors.New("hostlockdown: subprocess spawn succeeded after lockdown")
	}
	if isDenied(err) || errors.Is(err, syscall.EAGAIN) {
		return nil
	}
	return fmt.Errorf("hostlockdown: subprocess probe failed for an unrelated reason: %w", err)
}

// probeUnlistedOpenBlocked opens host paths outside every mount. The parent
// directory of each mount anchors the probe when it lies outside all mounts,
// so the probe works even when the system paths are missing. A fixed system
// path that lies inside a mount is no candidate.
func probeUnlistedOpenBlocked(mountsReal []string) error {
	var candidates []string
	for _, real := range mountsReal {
		candidates = append(candidates, filepath.Dir(real))
	}
	candidates = append(candidates, unlistedProbePaths...)
	var blocked int
	for _, path := range candidates {
		if !outsideAll(path, mountsReal) {
			continue
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
			return fmt.Errorf("hostlockdown: open of unlisted path %q succeeded after lockdown", path)
		}
		if isDenied(err) {
			blocked++
			continue
		}
		if !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("hostlockdown: unlisted-open probe of %q failed for an unrelated reason: %w", path, err)
		}
	}
	if blocked == 0 {
		return errors.New("hostlockdown: no probe path exists to verify the file-open lockdown")
	}
	return nil
}

// probeMountsReachable opens every mount directory. It proves that the allow
// rules of each mount match after parameter expansion.
func probeMountsReachable(mountsReal []string) error {
	for _, real := range mountsReal {
		fd, err := unix.Open(real, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("hostlockdown: open mount %q after lockdown: %w", real, err)
		}
		if err := unix.Close(fd); err != nil {
			return err
		}
	}
	return nil
}

// probeOutboundBlocked connects a TCP socket to a closed loopback port. A
// working lockdown rejects the connect before the TCP stack answers with
// ECONNREFUSED.
func probeOutboundBlocked() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		if isDenied(err) {
			return nil
		}
		return fmt.Errorf("hostlockdown: outbound probe socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	err = unix.Connect(fd, &unix.SockaddrInet4{Port: 1, Addr: [4]byte{127, 0, 0, 1}})
	switch {
	case isDenied(err):
		return nil
	case err == nil || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EINPROGRESS):
		return errors.New("hostlockdown: outbound TCP connect reached the network stack after lockdown")
	default:
		return fmt.Errorf("hostlockdown: outbound probe failed for an unrelated reason: %w", err)
	}
}
