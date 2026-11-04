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
// CAP_NET_BIND_SERVICE, and that each network namespace has its own value.
func portStartChecks() []check {
	var nobody, child *nsThread
	return []check{
		{"port-start-default-1024", func() error { return expectValue(portStartFile, "1024") }},
		{"root-binds-port-80", func() error { return expectBind(80, nil) }},
		{"start-nobody-thread", func() error {
			// The thread runs in the namespace of the probe, as nobody.
			t, err := newThread(false, true)
			if err != nil {
				return err
			}
			nobody = t
			return nil
		}},
		{"nobody-bind-below-1024-fails-with-eacces", func() error {
			return nobody.do(func() error {
				if err := expectBind(80, syscall.EACCES); err != nil {
					return err
				}
				return expectBind(1023, syscall.EACCES)
			})
		}},
		{"nobody-bind-1024-succeeds", func() error { return nobody.do(func() error { return expectBind(1024, nil) }) }},
		{"start-0-lets-nobody-bind-port-80", func() error {
			if err := writeAndExpect(portStartFile, "0", "0"); err != nil {
				return err
			}
			return nobody.do(func() error { return expectBind(80, nil) })
		}},
		{"start-1024-again-refuses-nobody", func() error {
			if err := writeAndExpect(portStartFile, "1024", "1024"); err != nil {
				return err
			}
			return nobody.do(func() error { return expectBind(80, syscall.EACCES) })
		}},
		{"child-netns-starts-at-1024", func() error {
			t, err := newNsThread()
			if err != nil {
				return err
			}
			child = t
			return child.do(func() error { return expectValue(portStartFile, "1024") })
		}},
		{"child-netns-write-keeps-parent-value", func() error {
			if err := child.do(func() error { return writeAndExpect(portStartFile, "0", "0") }); err != nil {
				return err
			}
			return expectValue(portStartFile, "1024")
		}},
		{"child-netns-start-0-lets-nobody-bind", func() error {
			return child.do(func() error {
				if err := dropPrivileges(); err != nil {
					return err
				}
				return expectBind(80, nil)
			})
		}},
		{"parent-netns-still-refuses-nobody", func() error {
			return nobody.do(func() error { return expectBind(80, syscall.EACCES) })
		}},
	}
}
