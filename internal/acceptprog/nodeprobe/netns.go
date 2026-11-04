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

//go:build linux

package main

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
)

// nsThread is a thread that runs functions for the probe. Linux gives a thread
// its own network namespace after unshare(CLONE_NEWNET) and its own user ID
// after a raw setuid call, so the probe runs the functions that need either
// on such a thread. The thread never returns to the Go scheduler and ends with
// its goroutine.
type nsThread struct {
	tasks chan func() error
	// fd is a descriptor of the network namespace of the thread.
	fd int
}

const nsThreadTimeout = 30 * time.Second

// newNsThread starts a thread in a new network namespace.
func newNsThread() (*nsThread, error) { return newThread(true, false) }

// newThread starts a thread. A thread with newNet set runs in a new network
// namespace. A thread with drop set runs as the user nobody.
func newThread(newNet, drop bool) (*nsThread, error) {
	t := &nsThread{tasks: make(chan func() error)}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if newNet {
			if _, _, errno := syscall.RawSyscall(syscall.SYS_UNSHARE, syscall.CLONE_NEWNET, 0, 0); errno != 0 {
				ready <- fmt.Errorf("unshare(CLONE_NEWNET): %w", errno)
				return
			}
		}
		fd, err := syscall.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", syscall.Gettid()), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			ready <- fmt.Errorf("open the network namespace: %w", err)
			return
		}
		t.fd = fd
		if drop {
			if err := dropPrivileges(); err != nil {
				ready <- err
				return
			}
		}
		ready <- nil
		for fn := range t.tasks {
			fn()
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			return nil, err
		}
		return t, nil
	case <-time.After(nsThreadTimeout):
		return nil, errors.New("the namespace thread did not start in 30s")
	}
}

// do runs fn on the thread and returns its error.
func (t *nsThread) do(fn func() error) error {
	done := make(chan error, 1)
	t.tasks <- func() error {
		done <- fn()
		return nil
	}
	select {
	case err := <-done:
		return err
	case <-time.After(nsThreadTimeout):
		return errors.New("the namespace thread gave no answer in 30s")
	}
}

// close ends the thread.
func (t *nsThread) close() {
	close(t.tasks)
}

// inNewNetns runs fn on a thread in a new network namespace.
func inNewNetns(fn func() error) error {
	t, err := newNsThread()
	if err != nil {
		return err
	}
	defer t.close()
	return t.do(fn)
}

// dropPrivileges makes the calling thread the user nobody. Only this thread
// changes, because the call is raw. Linux then clears the capabilities of the
// thread, so a later bind below the unprivileged port start fails.
func dropPrivileges() error {
	const nobody = 65534
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETUID, nobody, 0, 0); errno != 0 {
		return fmt.Errorf("setuid(%d): %w", nobody, errno)
	}
	return nil
}

// bindPort binds a new socket of the family and type to port on the wildcard
// address and closes it.
func bindPort(family, typ, port int) error {
	fd, err := syscall.Socket(family, typ, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("SO_REUSEADDR: %w", err)
	}
	var sa syscall.Sockaddr
	if family == syscall.AF_INET6 {
		sa = &syscall.SockaddrInet6{Port: port}
	} else {
		sa = &syscall.SockaddrInet4{Port: port}
	}
	return syscall.Bind(fd, sa)
}

// bindFamilies lists the socket kinds that the bind rule covers.
var bindFamilies = []struct {
	name        string
	family, typ int
}{
	{"tcp4", syscall.AF_INET, syscall.SOCK_STREAM},
	{"tcp6", syscall.AF_INET6, syscall.SOCK_STREAM},
	{"udp4", syscall.AF_INET, syscall.SOCK_DGRAM},
	{"udp6", syscall.AF_INET6, syscall.SOCK_DGRAM},
}

// expectBind binds every kind of socket to port and expects the result want:
// nil for success, or an errno.
func expectBind(port int, want error) error {
	for _, f := range bindFamilies {
		err := bindPort(f.family, f.typ, port)
		if want == nil && err != nil || want != nil && !errors.Is(err, want) {
			return fmt.Errorf("bind of %s port %d = %v, want %v", f.name, port, err, want)
		}
	}
	return nil
}
