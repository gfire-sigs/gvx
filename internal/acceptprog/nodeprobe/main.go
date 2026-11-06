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
//	nodeprobe kmsg                   check /dev/kmsg, syslog(2), and the sysctls of
//	                                 the kernel log; the check of kernel.dmesg_restrict
//	                                 runs the mode kmsg-unpriv as an ordinary user
//	nodeprobe kmsg-size BYTES        check that SIZE_BUFFER of syslog(2) returns BYTES
//	nodeprobe sysctls                check the stored sysctls
//	nodeprobe portstart              check ip_unprivileged_port_start
//	nodeprobe netsysctls             check the sysctls of a network namespace
//	nodeprobe forwarding             check forwarding between three namespaces
//	nodeprobe ethtool                check SIOCETHTOOL on a veth pair, a vxlan link,
//	                                 and lo, with the calls of Calico Felix
//	nodeprobe rpfilter               check the rp_filter files of the conf directories
//	                                 in the root namespace and in a child namespace
//	nodeprobe genl                   check NETLINK_GENERIC and the controller family
//	nodeprobe wireguard              check the wireguard link between two namespaces
//	nodeprobe wglimits               check the rules and limits of the wireguard link
//	nodeprobe vxlan                  check the vxlan link, neighbors, and the FDB
//	                                 with the calls of flannel between two namespaces
//	nodeprobe neighgc                check gc_thresh1 to gc_thresh3 of the neighbor
//	                                 tables and their effect on dynamic entries
//	nodeprobe recentparams           check the module parameters of xt_recent
//	nodeprobe capacity MEM CPUS      check MemTotal in bytes and the CPU count
//	nodeprobe memtotal WRITE_MIB DIR write WRITE_MIB MiB to the volume at DIR, print
//	                                 MemTotal, wait for the end of the input, and
//	                                 check that it stays
//	nodeprobe natmtu [MTU]           check the MTU of eth0 and of the tunnels on it
//	                                 in a sandbox with the NAT network; MTU is
//	                                 the expected MTU of eth0, 1500 by default
//	nodeprobe mtuset HOST:PORT       change the MTU of eth0 and of a veth link
//	                                 with netlink and with SIOCSIFMTU, check the
//	                                 range, the capability, the MTU of each veth
//	                                 end, and IPv6 below 1280, and move data
//	                                 through the NAT after a change; HOST:PORT is
//	                                 a throughput server
//	nodeprobe tput HOST:PORT MIB     measure the TCP download and upload rate of
//	                                 MIB MiB against a server at HOST:PORT
//	nodeprobe stats HOST:PORT        check link statistics; the probe reads from a
//	                                 TCP server at HOST:PORT
//	nodeprobe disks DIR HOST:PORT    check /proc/diskstats, /proc/partitions, and
//	                                 /sys/block against stat and mountinfo, and
//	                                 check that file I/O on the volume at DIR moves
//	                                 the counters and that socket and pipe traffic
//	                                 does not; the probe reads from a TCP server at
//	                                 HOST:PORT
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
	case "kmsg-size":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: nodeprobe kmsg-size BYTES")
			os.Exit(2)
		}
		want, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "kmsg-size: BYTES must be a number")
			os.Exit(2)
		}
		checks = kmsgSizeChecks(want)
	case "kmsg-unpriv":
		kmsgUnprivileged()
		return
	case "sysctls":
		checks = storedSysctlChecks()
	case "portstart":
		checks = portStartChecks()
	case "netsysctls":
		checks = netSysctlChecks()
	case "forwarding":
		checks = forwardingChecks()
	case "ethtool":
		checks = ethtoolChecks()
	case "rpfilter":
		checks = rpFilterChecks()
	case "genl":
		checks = genlChecks()
	case "wireguard":
		checks = wireguardChecks()
	case "wglimits":
		checks = wgLimitsChecks()
	case "wgstate":
		checks = wgStateChecks()
	case "vxlan":
		checks = vxlanChecks()
	case "natmtu":
		want := natEthernetMTU
		if len(os.Args) == 3 {
			var err error
			if want, err = strconv.Atoi(os.Args[2]); err != nil {
				fmt.Fprintln(os.Stderr, "natmtu: MTU must be a number")
				os.Exit(2)
			}
		}
		checks = natMTUChecks(want)
	case "mtuset":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: nodeprobe mtuset HOST:PORT")
			os.Exit(2)
		}
		checks = mtuSetChecks(os.Args[2])
	case "neighgc":
		checks = neighGCChecks()
	case "recentparams":
		checks = recentParamChecks()
	case "tput":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: nodeprobe tput HOST:PORT MIB")
			os.Exit(2)
		}
		mib, err := strconv.Atoi(os.Args[3])
		if err != nil || mib <= 0 {
			fmt.Fprintln(os.Stderr, "tput: MIB must be a positive number")
			os.Exit(2)
		}
		checks = tputChecks(os.Args[2], mib)
	case "wgchild":
		if err := wgChild(); err != nil {
			fmt.Fprintln(os.Stderr, "wgchild:", err)
			os.Exit(1)
		}
		return
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
	case "memtotal":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: nodeprobe memtotal WRITE_MIB DIR")
			os.Exit(2)
		}
		mib, err := strconv.Atoi(os.Args[2])
		if err != nil || mib < 0 {
			fmt.Fprintln(os.Stderr, "memtotal: WRITE_MIB must be a number")
			os.Exit(2)
		}
		checks = memTotalChecks(mib, os.Args[3])
	case "disks":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: nodeprobe disks DIR HOST:PORT")
			os.Exit(2)
		}
		checks = disksChecks(os.Args[2], os.Args[3])
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
