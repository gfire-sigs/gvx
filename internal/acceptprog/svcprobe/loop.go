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
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)

const (
	pingTimeout = 2 * time.Second
	// duplicateWindow is the time that the probe waits after an echo reply for a
	// second reply. A copy of a request that a node forwarded by mistake arrives
	// within a few milliseconds.
	duplicateWindow = 30 * time.Millisecond

	icmpEchoRequest = 8
	icmpEchoReply   = 0
)

// loop sends n echo requests and opens n TCP connections to host, alternately,
// and prints the counts of the failures and of the duplicate echo replies.
func loop(host, port string, n int) {
	target := net.ParseIP(host).To4()
	if target == nil {
		fmt.Fprintf(os.Stderr, "svcprobe: %q is not an IPv4 address\n", host)
		os.Exit(2)
	}
	conn, err := net.Dial("ip4:icmp", host)
	if err != nil {
		fmt.Fprintln(os.Stderr, "svcprobe: icmp socket:", err)
		os.Exit(1)
	}
	defer conn.Close()
	id := uint16(rand.Uint32())
	var pingLost, tcpFailed, duplicates int
	for i := range n {
		got, dups := echoOnce(conn, target, id, uint16(i))
		if !got {
			pingLost++
		}
		duplicates += dups
		if _, err := dialOnce(net.JoinHostPort(host, port), 0); err != nil {
			tcpFailed++
		}
	}
	fmt.Printf("LOOP ping_lost=%d tcp_failed=%d duplicates=%d\n", pingLost, tcpFailed, duplicates)
}

// echoOnce sends one echo request and waits for its reply. It reports whether
// a reply came and how many more replies for the same request followed.
func echoOnce(conn net.Conn, target net.IP, id, seq uint16) (got bool, duplicates int) {
	msg := make([]byte, 8+32)
	msg[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(msg[4:], id)
	binary.BigEndian.PutUint16(msg[6:], seq)
	binary.BigEndian.PutUint16(msg[2:], checksum(msg))
	conn.SetDeadline(time.Now().Add(pingTimeout))
	if _, err := conn.Write(msg); err != nil {
		return false, 0
	}
	buf := make([]byte, 2048)
	for {
		nr, err := conn.Read(buf)
		if err != nil {
			return got, duplicates
		}
		ip := buf[:nr]
		if len(ip) < 20 || ip[0]>>4 != 4 {
			continue
		}
		icmp := ip[int(ip[0]&0x0f)*4:]
		if len(icmp) < 8 || icmp[0] != icmpEchoReply || !net.IP(ip[12:16]).Equal(target) ||
			binary.BigEndian.Uint16(icmp[4:]) != id || binary.BigEndian.Uint16(icmp[6:]) != seq {
			continue
		}
		if got {
			duplicates++
			continue
		}
		got = true
		conn.SetDeadline(time.Now().Add(duplicateWindow))
	}
}

// checksum returns the Internet checksum of b.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
