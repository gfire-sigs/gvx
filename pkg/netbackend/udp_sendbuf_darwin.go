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

package netbackend

// udpSendBufferBytes is the send buffer of a host UDP socket. macOS refuses a
// datagram that is larger than this buffer with EMSGSIZE, and the buffer
// starts at net.inet.udp.maxdgram, which is 9216 bytes. A buffer of the size
// of the largest IPv4 datagram lets the relay send every datagram that the
// guest builds for an eth0 MTU above 9216.
const udpSendBufferBytes = 1 << 17

// widenUDPSend raises the send buffer of a host UDP socket, so that the relay
// can send a datagram of any size that the MTU of eth0 allows. A value that is
// not a socket that has a send buffer stays as it is.
func widenUDPSend(c any) {
	if s, ok := c.(interface{ SetWriteBuffer(int) error }); ok {
		_ = s.SetWriteBuffer(udpSendBufferBytes)
	}
}
