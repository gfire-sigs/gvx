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

//go:build linux || darwin

package control

import (
	"errors"
	"fmt"
	"net"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// SendFDs writes one sentinel byte accompanied by SCM_RIGHTS file descriptors
// over a Unix domain connection.
func SendFDs(conn net.Conn, fds []int) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return NewError(CodeUnsupported, "file descriptor passing requires a Unix domain socket")
	}
	if len(fds) == 0 {
		return nil
	}
	oob := unix.UnixRights(fds...)
	n, oobn, err := uc.WriteMsgUnix([]byte{0}, oob, nil)
	if err != nil {
		return fmt.Errorf("send SCM_RIGHTS: %w", err)
	}
	if n != 1 || oobn != len(oob) {
		return errors.New("short SCM_RIGHTS write")
	}
	return nil
}

// RecvFDs reads one sentinel byte and its attached SCM_RIGHTS file descriptors
// from a Unix domain connection. Callers own all returned descriptors.
func RecvFDs(conn net.Conn, maxFDs int) ([]int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, NewError(CodeUnsupported, "file descriptor passing requires a Unix domain socket")
	}
	if maxFDs <= 0 {
		maxFDs = 4
	}
	var sentinel [1]byte
	oob := make([]byte, unix.CmsgSpace(4*maxFDs))
	n, oobn, _, _, err := uc.ReadMsgUnix(sentinel[:], oob)
	if err != nil {
		return nil, fmt.Errorf("recv SCM_RIGHTS: %w", err)
	}
	if n != 1 {
		return nil, errors.New("short SCM_RIGHTS read")
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("parse SCM_RIGHTS control message: %w", err)
	}
	var fds []int
	for i := range cmsgs {
		parsed, err := unix.ParseUnixRights(&cmsgs[i])
		if err != nil {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
			return nil, fmt.Errorf("parse SCM_RIGHTS fds: %w", err)
		}
		fds = append(fds, parsed...)
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
	}
	return fds, nil
}
