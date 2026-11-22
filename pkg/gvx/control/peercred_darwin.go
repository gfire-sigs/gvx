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

package control

import (
	"fmt"
	"net"
	"os"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// VerifyPeerCredentials verifies that a Unix domain socket peer runs under the
// same effective user ID as the server process via LOCAL_PEERCRED.
func VerifyPeerCredentials(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("peer credentials syscall conn: %w", err)
	}
	var credErr error
	var peerUID uint32
	if err := raw.Control(func(fd uintptr) {
		xucred, err := unix.GetsockoptXucred(int(fd), 0 /* SOL_LOCAL */, unix.LOCAL_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		peerUID = xucred.Uid
	}); err != nil {
		return fmt.Errorf("peer credentials control: %w", err)
	}
	if credErr != nil {
		return fmt.Errorf("LOCAL_PEERCRED: %w", credErr)
	}
	wantUID := uint32(os.Geteuid())
	if peerUID != wantUID {
		return fmt.Errorf("unauthorized peer uid %d (want %d)", peerUID, wantUID)
	}
	return nil
}
