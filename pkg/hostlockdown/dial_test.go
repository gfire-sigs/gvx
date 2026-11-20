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

package hostlockdown

import "testing"

func TestListenLoopbackValidation(t *testing.T) {
	for _, tc := range []struct {
		network string
		addr    string
	}{
		{"unix", "/tmp/test.sock"},
		{"tcp", "0.0.0.0:0"},
		{"tcp", ":0"},
		{"tcp", "localhost:0"},
		{"tcp", "10.0.0.1:0"},
		{"tcp6", "[::]:0"},
	} {
		if ln, err := ListenLoopback(tc.network, tc.addr); err == nil {
			_ = ln.Close()
			t.Fatalf("ListenLoopback(%q, %q) succeeded, want error", tc.network, tc.addr)
		}
	}
	for _, tc := range []struct {
		network string
		addr    string
	}{
		{"unixgram", "/tmp/test.sock"},
		{"udp", "0.0.0.0:0"},
		{"udp", ":0"},
		{"udp", "10.0.0.1:0"},
	} {
		if pc, err := ListenPacketLoopback(tc.network, tc.addr); err == nil {
			_ = pc.Close()
			t.Fatalf("ListenPacketLoopback(%q, %q) succeeded, want error", tc.network, tc.addr)
		}
	}
}
