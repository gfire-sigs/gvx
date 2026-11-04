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

import "syscall"

const portStartFile = netIPv4 + "ip_unprivileged_port_start"

// portStartChecks checks that a bind below ip_unprivileged_port_start needs
// CAP_NET_BIND_SERVICE, and that each network namespace has its own value. The
// root namespace of the sandbox is the namespace of the container, so it starts
// at 0, as in a Docker container. A namespace that the guest creates starts at
// 1024, as on Linux.
func portStartChecks() []check {
	var nobody, childNobody, child *nsThread
	return []check{
		{"root-netns-starts-at-0", func() error { return expectValue(portStartFile, "0") }},
		{"start-nobody-thread", func() error {
			// The thread runs in the namespace of the probe, as nobody.
			t, err := newThread(false, true)
			if err != nil {
				return err
			}
			nobody = t
			return nil
		}},
		{"root-netns-lets-nobody-bind-port-80", func() error {
			return nobody.do(func() error { return expectBind(80, nil) })
		}},
		{"start-1024-refuses-nobody-below-1024", func() error {
			if err := writeAndExpect(portStartFile, "1024", "1024"); err != nil {
				return err
			}
			return nobody.do(func() error {
				if err := expectBind(80, syscall.EACCES); err != nil {
					return err
				}
				return expectBind(1023, syscall.EACCES)
			})
		}},
		{"start-1024-lets-nobody-bind-1024", func() error { return nobody.do(func() error { return expectBind(1024, nil) }) }},
		{"root-binds-port-80-at-1024", func() error { return expectBind(80, nil) }},
		{"start-0-lets-nobody-bind-port-80", func() error {
			if err := writeAndExpect(portStartFile, "0", "0"); err != nil {
				return err
			}
			return nobody.do(func() error { return expectBind(80, nil) })
		}},
		{"child-netns-starts-at-1024", func() error {
			t, err := newThread(true, true)
			if err != nil {
				return err
			}
			childNobody = t
			return childNobody.do(func() error { return expectValue(portStartFile, "1024") })
		}},
		{"child-netns-refuses-nobody-below-1024", func() error {
			return childNobody.do(func() error {
				if err := expectBind(80, syscall.EACCES); err != nil {
					return err
				}
				return expectBind(1024, nil)
			})
		}},
		{"child-netns-write-keeps-parent-value", func() error {
			t, err := newNsThread()
			if err != nil {
				return err
			}
			child = t
			if err := child.do(func() error { return writeAndExpect(portStartFile, "2000", "2000") }); err != nil {
				return err
			}
			return expectValue(portStartFile, "0")
		}},
		{"child-netns-value-leaves-parent-binds", func() error {
			return nobody.do(func() error { return expectBind(80, nil) })
		}},
	}
}
