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
	n, oobn, flags, _, readErr := uc.ReadMsgUnix(sentinel[:], oob)

	// Always parse any ancillary control messages returned by the kernel so
	// received descriptors are closed on every error path.
	var fds []int
	var parseErr error
	if oobn > 0 {
		cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			parseErr = fmt.Errorf("parse SCM_RIGHTS control message: %w", err)
		} else {
			for i := range cmsgs {
				parsed, err := unix.ParseUnixRights(&cmsgs[i])
				if err != nil {
					parseErr = fmt.Errorf("parse SCM_RIGHTS fds: %w", err)
					continue
				}
				fds = append(fds, parsed...)
			}
		}
	}
	closeAll := func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}
	if readErr != nil {
		closeAll()
		return nil, fmt.Errorf("recv SCM_RIGHTS: %w", readErr)
	}
	if flags&unix.MSG_CTRUNC != 0 {
		closeAll()
		return nil, errors.New("truncated SCM_RIGHTS control message")
	}
	if n != 1 {
		closeAll()
		return nil, errors.New("short SCM_RIGHTS read")
	}
	if parseErr != nil {
		closeAll()
		return nil, parseErr
	}
	if len(fds) > maxFDs {
		closeAll()
		return nil, fmt.Errorf("received %d SCM_RIGHTS fds (max %d)", len(fds), maxFDs)
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
	}
	return fds, nil
}
