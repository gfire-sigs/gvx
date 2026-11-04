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

// Command nodeprobe checks the guest kernel interfaces that a Kubernetes node
// agent needs: /dev/kmsg, the stored and per-namespace sysctls, the bind rule
// of ip_unprivileged_port_start, forwarding between network namespaces, the
// node capacity, and the statistics of links and disks. Each check prints
// "PASS name" or "FAIL name: reason". The probe runs as root in a guest without
// an image.
//
// Usage:
//
//	nodeprobe kmsg                   check /dev/kmsg
//	nodeprobe sysctls                check the stored sysctls
//	nodeprobe portstart              check ip_unprivileged_port_start
//	nodeprobe netsysctls             check the sysctls of a network namespace
//	nodeprobe forwarding             check forwarding between three namespaces
//	nodeprobe capacity MEM CPUS      check MemTotal in bytes and the CPU count
//	nodeprobe stats HOST:PORT        check link and disk statistics; the probe
//	                                 reads from a TCP server at HOST:PORT
package main

import (
	"fmt"
	"os"
	"strconv"
)

// check is one named step of a mode.
type check struct {
	name string
	run  func() error
}

// runChecks runs the checks in order, prints one line for each, and prints DONE.
// It returns false when a check failed.
func runChecks(checks []check) bool {
	ok := true
	for _, c := range checks {
		if err := c.run(); err != nil {
			fmt.Printf("FAIL %s: %v\n", c.name, err)
			ok = false
			continue
		}
		fmt.Printf("PASS %s\n", c.name)
	}
	fmt.Println("DONE")
	return ok
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: nodeprobe kmsg|sysctls|portstart|netsysctls|forwarding|capacity|stats")
		os.Exit(2)
	}
	var checks []check
	switch os.Args[1] {
	case "kmsg":
		checks = kmsgChecks()
	case "sysctls":
		checks = storedSysctlChecks()
	case "portstart":
		checks = portStartChecks()
	case "netsysctls":
		checks = netSysctlChecks()
	case "forwarding":
		checks = forwardingChecks()
	case "capacity":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: nodeprobe capacity MEM_BYTES CPUS")
			os.Exit(2)
		}
		mem, err1 := strconv.ParseUint(os.Args[2], 10, 64)
		cpus, err2 := strconv.Atoi(os.Args[3])
		if err1 != nil || err2 != nil {
			fmt.Fprintln(os.Stderr, "capacity: MEM_BYTES and CPUS must be numbers")
			os.Exit(2)
		}
		checks = capacityChecks(mem, cpus)
	case "stats":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: nodeprobe stats HOST:PORT")
			os.Exit(2)
		}
		checks = statsChecks(os.Args[2])
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
	if !runChecks(checks) {
		os.Exit(1)
	}
}
