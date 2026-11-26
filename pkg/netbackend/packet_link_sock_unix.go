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

//go:build unix

package netbackend

import (
	"fmt"
	"syscall"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// validateStreamSocket rejects non-stream sockets (such as SOCK_DGRAM or
// SOCK_SEQPACKET) when the descriptor reports SO_TYPE. Non-socket descriptors
// return an error from getsockopt and are allowed.
func validateStreamSocket(sc syscall.Conn) error {
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	var sockType int
	var sockErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		sockType, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
	}); ctrlErr != nil || sockErr != nil {
		return nil
	}
	if sockType != unix.SOCK_STREAM {
		return fmt.Errorf("%w: packet link connection socket type %d is not SOCK_STREAM", ErrInvalidPacketLinkConfig, sockType)
	}
	return nil
}
