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

// Command ctprobe reads and deletes tracked connections through the Go library
// github.com/vishvananda/netlink, the way kube-proxy cleans up the connections
// of a UDP service. Each check prints "PASS name" or "FAIL name: reason". The
// probe runs as root in a guest whose nat OUTPUT chain holds these rules, which
// the caller installs with iptables:
//
//	-d 127.0.0.2 -p udp --dport 9000 -j DNAT --to-destination 127.0.0.1:9001
//	-d 127.0.0.2 -p tcp --dport 9100 -j DNAT --to-destination 127.0.0.1:9101
//
// Usage:
//
//	ctprobe kubeproxy    list the flows, delete the UDP flow with a filter, and
//	                     send again
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	udpVirtual   = "127.0.0.2:9000"
	udpBackend   = "127.0.0.1:9001"
	tcpVirtual   = "127.0.0.2:9100"
	tcpBackend   = "127.0.0.1:9101"
	udpLocalPort = 5555
)

// check is one named step. run returns nil when the step passed.
type check struct {
	name string
	run  func() error
}

func main() {
	if len(os.Args) != 2 || os.Args[1] != "kubeproxy" {
		fmt.Fprintln(os.Stderr, "usage: ctprobe kubeproxy")
		os.Exit(2)
	}
	s := &scenario{}
	defer s.close()
	checks := []check{
		{"listeners-start", s.startListeners},
		{"udp-flow-reaches-the-backend", s.sendUDP},
		{"udp-flow-is-listed-with-both-tuples", s.listUDPFlow},
		{"tcp-flow-is-listed-as-established", s.listTCPFlow},
		{"ipv6-table-lists-without-error", s.listIPv6},
		{"delete-filter-removes-the-udp-flow-only", s.deleteUDPFlow},
		{"udp-flow-is-gone-after-the-delete", s.udpFlowGone},
		{"delete-filter-matches-nothing-twice", s.deleteAgain},
		{"next-udp-packet-starts-a-new-flow", s.newFlowAppears},
	}
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
	if !ok {
		os.Exit(1)
	}
}

// scenario holds the sockets of the run.
type scenario struct {
	udpListener *net.UDPConn
	tcpListener net.Listener
	tcpClient   net.Conn
	tcpServer   net.Conn
	udpClient   *net.UDPConn
	firstID     uint32
}

func (s *scenario) close() {
	for _, c := range []io.Closer{s.udpListener, s.tcpListener, s.tcpClient, s.tcpServer, s.udpClient} {
		if c != nil {
			c.Close()
		}
	}
}

func (s *scenario) startListeners() error {
	addr, err := net.ResolveUDPAddr("udp", udpBackend)
	if err != nil {
		return err
	}
	if s.udpListener, err = net.ListenUDP("udp", addr); err != nil {
		return err
	}
	if s.tcpListener, err = net.Listen("tcp", tcpBackend); err != nil {
		return err
	}
	return nil
}

// sendUDP sends a datagram from a fixed port to the virtual address and waits
// for the backend to receive it.
func (s *scenario) sendUDP() error {
	if s.udpClient == nil {
		dst, err := net.ResolveUDPAddr("udp", udpVirtual)
		if err != nil {
			return err
		}
		if s.udpClient, err = net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: udpLocalPort}, dst); err != nil {
			return err
		}
	}
	return s.deliverUDP("hello")
}

// deliverUDP sends msg on the client socket and requires the backend to read it.
func (s *scenario) deliverUDP(msg string) error {
	if _, err := s.udpClient.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, 64)
	s.udpListener.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := s.udpListener.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("the backend read nothing: %w", err)
	}
	if string(buf[:n]) != msg {
		return fmt.Errorf("the backend read %q, want %q", buf[:n], msg)
	}
	return nil
}

// findFlow returns the flow of the protocol with the original destination port.
func findFlow(family netlink.InetFamily, proto uint8, dport uint16) (*netlink.ConntrackFlow, error) {
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
	if err != nil {
		return nil, fmt.Errorf("ConntrackTableList: %w", err)
	}
	for _, f := range flows {
		if f.Forward.Protocol == proto && f.Forward.DstPort == dport {
			return f, nil
		}
	}
	return nil, fmt.Errorf("no flow of protocol %d to port %d among %d flows", proto, dport, len(flows))
}

func (s *scenario) listUDPFlow() error {
	f, err := findFlow(netlink.FAMILY_V4, unix.IPPROTO_UDP, 9000)
	if err != nil {
		return err
	}
	switch {
	case !f.Forward.DstIP.Equal(net.IPv4(127, 0, 0, 2)):
		return fmt.Errorf("original destination = %s, want 127.0.0.2", f.Forward.DstIP)
	case f.Forward.SrcPort != udpLocalPort:
		return fmt.Errorf("original source port = %d, want %d", f.Forward.SrcPort, udpLocalPort)
	case !f.Reverse.SrcIP.Equal(net.IPv4(127, 0, 0, 1)) || f.Reverse.SrcPort != 9001:
		return fmt.Errorf("reply source = %s:%d, want the backend 127.0.0.1:9001", f.Reverse.SrcIP, f.Reverse.SrcPort)
	case f.Reverse.DstPort != udpLocalPort:
		return fmt.Errorf("reply destination port = %d, want %d", f.Reverse.DstPort, udpLocalPort)
	case f.TimeOut == 0 || f.TimeOut > 600:
		return fmt.Errorf("timeout = %d seconds, want 1 to 600", f.TimeOut)
	case f.Mark != 0:
		return fmt.Errorf("mark = %d, want 0", f.Mark)
	}
	return nil
}

func (s *scenario) listTCPFlow() error {
	var err error
	if s.tcpClient, err = net.DialTimeout("tcp", tcpVirtual, 5*time.Second); err != nil {
		return err
	}
	if s.tcpServer, err = s.tcpListener.Accept(); err != nil {
		return err
	}
	// One round trip makes sure the connection tracker saw the handshake end.
	if _, err := s.tcpClient.Write([]byte("x")); err != nil {
		return err
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(s.tcpServer, buf); err != nil {
		return err
	}
	f, err := findFlow(netlink.FAMILY_V4, unix.IPPROTO_TCP, 9100)
	if err != nil {
		return err
	}
	info, ok := f.ProtoInfo.(*netlink.ProtoInfoTCP)
	if !ok {
		return fmt.Errorf("protocol info = %T, want TCP", f.ProtoInfo)
	}
	// TCP_CONNTRACK_ESTABLISHED is 3.
	if info.State != 3 {
		return fmt.Errorf("TCP state = %d, want 3 (ESTABLISHED)", info.State)
	}
	if f.Reverse.SrcPort != 9101 {
		return fmt.Errorf("reply source port = %d, want 9101", f.Reverse.SrcPort)
	}
	return nil
}

func (s *scenario) listIPv6() error {
	_, err := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V6)
	return err
}

// udpFilter selects the UDP flow the way kube-proxy selects the flows of a
// service endpoint: the protocol, the original destination, and the reply source.
func udpFilter() (*netlink.ConntrackFilter, error) {
	filter := &netlink.ConntrackFilter{}
	if err := filter.AddProtocol(unix.IPPROTO_UDP); err != nil {
		return nil, err
	}
	if err := filter.AddIP(netlink.ConntrackOrigDstIP, net.IPv4(127, 0, 0, 2)); err != nil {
		return nil, err
	}
	if err := filter.AddPort(netlink.ConntrackOrigDstPort, 9000); err != nil {
		return nil, err
	}
	if err := filter.AddIP(netlink.ConntrackReplySrcIP, net.IPv4(127, 0, 0, 1)); err != nil {
		return nil, err
	}
	return filter, nil
}

func (s *scenario) deleteUDPFlow() error {
	filter, err := udpFilter()
	if err != nil {
		return err
	}
	deleted, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, netlink.FAMILY_V4, filter)
	if err != nil {
		return fmt.Errorf("ConntrackDeleteFilters: %w", err)
	}
	if deleted != 1 {
		return fmt.Errorf("deleted %d flows, want 1", deleted)
	}
	if _, err := findFlow(netlink.FAMILY_V4, unix.IPPROTO_TCP, 9100); err != nil {
		return fmt.Errorf("the delete removed the TCP flow too: %w", err)
	}
	return nil
}

func (s *scenario) udpFlowGone() error {
	if _, err := findFlow(netlink.FAMILY_V4, unix.IPPROTO_UDP, 9000); err == nil {
		return fmt.Errorf("the UDP flow is still listed")
	}
	return nil
}

func (s *scenario) deleteAgain() error {
	filter, err := udpFilter()
	if err != nil {
		return err
	}
	deleted, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, netlink.FAMILY_V4, filter)
	if err != nil {
		return fmt.Errorf("ConntrackDeleteFilters: %w", err)
	}
	if deleted != 0 {
		return fmt.Errorf("deleted %d flows, want 0", deleted)
	}
	return nil
}

func (s *scenario) newFlowAppears() error {
	if err := s.deliverUDP("again"); err != nil {
		return err
	}
	_, err := findFlow(netlink.FAMILY_V4, unix.IPPROTO_UDP, 9000)
	return err
}
