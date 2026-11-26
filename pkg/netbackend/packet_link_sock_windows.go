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

//go:build windows

package netbackend

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

// winSOType is WinSock2 SO_TYPE (not exported by golang.org/x/sys/windows).
const winSOType = 0x1008

// validateStreamSocket rejects non-stream sockets (such as SOCK_DGRAM) when the
// handle reports SO_TYPE. Non-socket handles (such as named pipes) return an
// error from getsockopt and are allowed.
func validateStreamSocket(sc syscall.Conn) error {
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	var sockType int
	var sockErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		sockType, sockErr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, winSOType)
	}); ctrlErr != nil || sockErr != nil {
		return nil
	}
	if sockType != windows.SOCK_STREAM {
		return fmt.Errorf("%w: packet link connection socket type %d is not SOCK_STREAM", ErrInvalidPacketLinkConfig, sockType)
	}
	return nil
}
