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

// Command svcprobe is a TCP server and a TCP client for tests that move
// connections with NAT rules. The server answers each connection with its name
// and the address that it sees as the peer. The client prints the answer.
//
// Usage:
//
//	svcprobe serve ADDR NAME   listen on ADDR (HOST:PORT) until the process ends
//	svcprobe dial ADDR [PORT]  connect to ADDR and print one line:
//	                           "REPLY NAME from=PEER" or "ERROR reason"
//	                           PORT binds the local port of the client
//	svcprobe loop HOST PORT N  send N ICMP echo requests to HOST and open N TCP
//	                           connections to HOST:PORT, one after the other,
//	                           and print one line:
//	                           "LOOP ping_lost=P tcp_failed=T duplicates=D"
//	                           A duplicate is a second echo reply for a request.
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

const dialTimeout = 3 * time.Second

func main() {
	switch {
	case len(os.Args) == 4 && os.Args[1] == "serve":
		serve(os.Args[2], os.Args[3])
	case len(os.Args) == 5 && os.Args[1] == "loop":
		n, err := strconv.Atoi(os.Args[4])
		if err != nil || n < 1 {
			fmt.Fprintf(os.Stderr, "svcprobe: invalid count %q\n", os.Args[4])
			os.Exit(2)
		}
		loop(os.Args[2], os.Args[3], n)
	case len(os.Args) == 3 && os.Args[1] == "dial":
		dial(os.Args[2], 0)
	case len(os.Args) == 4 && os.Args[1] == "dial":
		port, err := strconv.Atoi(os.Args[3])
		if err != nil || port < 1 || port > 65535 {
			fmt.Fprintf(os.Stderr, "svcprobe: invalid local port %q\n", os.Args[3])
			os.Exit(2)
		}
		dial(os.Args[2], port)
	default:
		fmt.Fprintln(os.Stderr, "usage: svcprobe serve ADDR NAME | svcprobe dial ADDR [PORT] | svcprobe loop HOST PORT N")
		os.Exit(2)
	}
}

func serve(addr, name string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "accept:", err)
			os.Exit(1)
		}
		peer, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Fprintf(conn, "%s from=%s\n", name, peer)
		conn.Close()
	}
}

// dial connects to addr and prints the answer. A positive localPort binds the
// source port of the connection.
func dial(addr string, localPort int) {
	reply, err := dialOnce(addr, localPort)
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
	fmt.Printf("REPLY %s", reply)
}

// dialOnce connects to addr and returns the answer of the server.
func dialOnce(addr string, localPort int) ([]byte, error) {
	d := net.Dialer{Timeout: dialTimeout}
	if localPort > 0 {
		d.LocalAddr = &net.TCPAddr{Port: localPort}
	}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(dialTimeout))
	reply, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(reply) == 0 {
		return nil, errors.New("read: empty answer")
	}
	return reply, nil
}
