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

import (
	"maps"
	"testing"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/waiter"
)

func nicNames(s *stack.Stack) map[tcpip.NICID]string {
	names := make(map[tcpip.NICID]string)
	for id, info := range s.NICInfo() {
		names[id] = info.Name
	}
	return names
}

// ip(8), Docker, and netlink clients find a link by its name. The loopback
// device must also have the interface index 1, as on Linux.
func TestStacksNameTheirNICs(t *testing.T) {
	nat, fwd, err := NewNATStack(NATConfig{})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	defer func() {
		_ = fwd.Close()
		nat.Close()
	}()
	if got, want := nicNames(nat), map[tcpip.NICID]string{1: "lo", 2: "eth0"}; !maps.Equal(got, want) {
		t.Errorf("NAT stack NICs = %v, want %v", got, want)
	}

	// A new guest network namespace gets this stack.
	ns, err := NewLoopbackStack(StackOptions{})
	if err != nil {
		t.Fatalf("NewLoopbackStack: %v", err)
	}
	defer ns.Close()
	if got, want := nicNames(ns), map[tcpip.NICID]string{1: "lo"}; !maps.Equal(got, want) {
		t.Errorf("namespace stack NICs = %v, want %v", got, want)
	}
}

func TestRawSocketsNeedTheOption(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opts    StackOptions
		wantRaw bool
	}{
		{name: "default", opts: StackOptions{}, wantRaw: false},
		{name: "raw", opts: StackOptions{RawSockets: true}, wantRaw: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewLoopbackStack(tc.opts)
			if err != nil {
				t.Fatalf("NewLoopbackStack: %v", err)
			}
			defer s.Close()
			var wq waiter.Queue
			ep, tcpipErr := s.NewRawEndpoint(header.ICMPv4ProtocolNumber, ipv4.ProtocolNumber, &wq, true)
			if ep != nil {
				ep.Close()
			}
			if got := tcpipErr == nil; got != tc.wantRaw {
				t.Errorf("NewRawEndpoint error = %v, want success %t", tcpipErr, tc.wantRaw)
			}
		})
	}
}
