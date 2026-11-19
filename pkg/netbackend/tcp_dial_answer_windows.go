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
	"syscall"

	"golang.org/x/sys/windows"
)

// dialErrnoAnswer selects the answer to a guest SYN from the Windows Sockets
// code of a failed host connect. Go reads the result of ConnectEx with
// WSAGetOverlappedResult, so the code is a WSAE code. WSAECONNREFUSED and
// every code of no known class get a RST.
func dialErrnoAnswer(errno syscall.Errno) dialAnswer {
	switch errno {
	case windows.WSAETIMEDOUT:
		return answerNone
	case windows.WSAEHOSTUNREACH, windows.WSAEHOSTDOWN:
		return answerHostUnreachable
	case windows.WSAENETUNREACH:
		return answerNetUnreachable
	default:
		return answerReset
	}
}
