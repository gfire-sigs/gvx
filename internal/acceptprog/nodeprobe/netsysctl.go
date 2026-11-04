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

import (
	"fmt"
	"syscall"
)

// keepaliveOptions reads the keepalive parameters of a new TCP socket in the
// network namespace of the calling thread: idle time, interval, and probe count.
func keepaliveOptions() (idle, interval, probes int, err error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	defer syscall.Close(fd)
	get := func(opt int) (int, error) { return syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, opt) }
	if idle, err = get(syscall.TCP_KEEPIDLE); err != nil {
		return 0, 0, 0, fmt.Errorf("TCP_KEEPIDLE: %w", err)
	}
	if interval, err = get(syscall.TCP_KEEPINTVL); err != nil {
		return 0, 0, 0, fmt.Errorf("TCP_KEEPINTVL: %w", err)
	}
	if probes, err = get(syscall.TCP_KEEPCNT); err != nil {
		return 0, 0, 0, fmt.Errorf("TCP_KEEPCNT: %w", err)
	}
	return idle, interval, probes, nil
}

// ephemeralPort binds a UDP socket to port 0 and returns the port that the
// stack picked in the network namespace of the calling thread.
func ephemeralPort() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{}); err != nil {
		return 0, err
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return 0, err
	}
	return sa.(*syscall.SockaddrInet4).Port, nil
}

// netSysctlChecks checks the sysctls that Kubernetes allows a pod to set. Each
// one must be writable in a new network namespace and must leave the value of
// the parent namespace alone.
func netSysctlChecks() []check {
	var child *nsThread
	parentBefore := map[string]string{}
	var checks []check
	checks = append(checks,
		check{"parent-values-before", func() error {
			for _, s := range netSysctls {
				got, err := readValue(netIPv4 + s.name)
				if err != nil {
					return err
				}
				if s.def != unknownDefault && got != s.def {
					return fmt.Errorf("%s reads %q, want the default %q", s.name, got, s.def)
				}
				parentBefore[s.name] = got
			}
			return nil
		}},
		check{"child-netns-starts", func() error {
			t, err := newNsThread()
			if err != nil {
				return err
			}
			child = t
			return nil
		}},
		check{"child-netns-has-the-defaults", func() error {
			return child.do(func() error {
				for _, s := range netSysctls {
					if s.def == unknownDefault {
						continue
					}
					if err := expectValue(netIPv4+s.name, s.def); err != nil {
						return err
					}
				}
				return nil
			})
		}},
	)
	for _, s := range netSysctls {
		checks = append(checks, check{"child-netns-writes " + s.name, func() error {
			err := child.do(func() error {
				if err := writeAndExpect(netIPv4+s.name, s.write+"\n", s.want); err != nil {
					return err
				}
				for _, text := range s.invalid {
					if err := rejectValue(netIPv4+s.name, text); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			return expectValue(netIPv4+s.name, parentBefore[s.name])
		}})
	}
	checks = append(checks,
		check{"ping-group-range-reversed-reads-1-0", func() error {
			return child.do(func() error { return writeAndExpect(netIPv4+"ping_group_range", "10 5", "1 0") })
		}},
		check{"child-keepalive-reaches-new-sockets", func() error {
			err := child.do(func() error {
				idle, interval, probes, err := keepaliveOptions()
				if err != nil {
					return err
				}
				if idle != 1800 || interval != 30 || probes != 5 {
					return fmt.Errorf("a new socket has keepalive %d/%d/%d, want 1800/30/5", idle, interval, probes)
				}
				return nil
			})
			if err != nil {
				return err
			}
			idle, interval, probes, err := keepaliveOptions()
			if err != nil {
				return err
			}
			if idle != 7200 || interval != 75 || probes != 9 {
				return fmt.Errorf("a new socket of the parent has keepalive %d/%d/%d, want 7200/75/9", idle, interval, probes)
			}
			return nil
		}},
		check{"child-port-range-reaches-bind", func() error {
			return child.do(func() error {
				for range 5 {
					port, err := ephemeralPort()
					if err != nil {
						return err
					}
					if port < 40000 || port > 40010 {
						return fmt.Errorf("the stack picked port %d, want a port in 40000-40010", port)
					}
				}
				return nil
			})
		}},
		check{"parent-values-after", func() error {
			for _, s := range netSysctls {
				if err := expectValue(netIPv4+s.name, parentBefore[s.name]); err != nil {
					return err
				}
			}
			return nil
		}},
	)
	return checks
}
