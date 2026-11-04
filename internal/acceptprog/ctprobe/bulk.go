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
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// bulkFlows is the number of flows of the bulk modes. It is more than five
	// times the 900 entries that fit one answer of the former dump.
	bulkFlows = 5000
	// bulkFirstPort is the first destination port of the flows.
	bulkFirstPort = 20000
)

var bulkVirtual = net.IPv4(127, 0, 0, 2)

// runBulk runs one step of the bulk mode and returns the exit status.
func runBulk(step string) int {
	var err error
	switch step {
	case "create":
		err = bulkCreate()
	case "list":
		err = bulkList()
	case "delete":
		err = bulkDelete()
	default:
		fmt.Printf("FAIL bulk: unknown step %q\n", step)
		return 2
	}
	if err != nil {
		fmt.Printf("FAIL bulk-%s: %v\n", step, err)
		return 1
	}
	fmt.Printf("PASS bulk-%s\n", step)
	return 0
}

// bulkCreate sends one datagram from one socket to each destination port. The
// datagrams differ in the destination port, so each one makes its own flow.
func bulkCreate() error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer conn.Close()
	for i := range bulkFlows {
		if _, err := conn.WriteToUDP([]byte("x"), &net.UDPAddr{IP: bulkVirtual, Port: bulkFirstPort + i}); err != nil {
			return fmt.Errorf("send %d: %w", i, err)
		}
	}
	return nil
}

// bulkPorts lists the table and returns the number of flows to each original
// destination port of the bulk flows.
func bulkPorts() (map[uint16]int, error) {
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
	if err != nil {
		// ErrDumpInterrupted means that the answer is incomplete.
		return nil, fmt.Errorf("ConntrackTableList: %w", err)
	}
	ports := make(map[uint16]int)
	for _, f := range flows {
		if f.Forward.Protocol == unix.IPPROTO_UDP && f.Forward.DstIP.Equal(bulkVirtual) {
			ports[f.Forward.DstPort]++
		}
	}
	return ports, nil
}

// bulkList requires one flow for each destination port.
func bulkList() error {
	ports, err := bulkPorts()
	if err != nil {
		return err
	}
	for i := range bulkFlows {
		if n := ports[uint16(bulkFirstPort+i)]; n != 1 {
			return fmt.Errorf("the listing holds %d flows to port %d, want 1 (%d ports found)", n, bulkFirstPort+i, len(ports))
		}
	}
	if len(ports) != bulkFlows {
		return fmt.Errorf("the listing holds %d ports, want %d", len(ports), bulkFlows)
	}
	return nil
}

// bulkDelete deletes the flows with a filter on the protocol and the original
// destination, and it requires an empty table afterwards.
func bulkDelete() error {
	filter := &netlink.ConntrackFilter{}
	if err := filter.AddProtocol(unix.IPPROTO_UDP); err != nil {
		return err
	}
	if err := filter.AddIP(netlink.ConntrackOrigDstIP, bulkVirtual); err != nil {
		return err
	}
	deleted, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, netlink.FAMILY_V4, filter)
	if err != nil {
		return fmt.Errorf("ConntrackDeleteFilters: %w", err)
	}
	if deleted != bulkFlows {
		return fmt.Errorf("deleted %d flows, want %d", deleted, bulkFlows)
	}
	ports, err := bulkPorts()
	if err != nil {
		return err
	}
	if len(ports) != 0 {
		return fmt.Errorf("%d flows remain after the delete", len(ports))
	}
	return nil
}
