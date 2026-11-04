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
//	svcprobe dial ADDR         connect to ADDR and print one line:
//	                           "REPLY NAME from=PEER" or "ERROR reason"
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const dialTimeout = 3 * time.Second

func main() {
	switch {
	case len(os.Args) == 4 && os.Args[1] == "serve":
		serve(os.Args[2], os.Args[3])
	case len(os.Args) == 3 && os.Args[1] == "dial":
		dial(os.Args[2])
	default:
		fmt.Fprintln(os.Stderr, "usage: svcprobe serve ADDR NAME | svcprobe dial ADDR")
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

func dial(addr string) {
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(dialTimeout))
	reply, err := io.ReadAll(conn)
	if err != nil || len(reply) == 0 {
		fmt.Println("ERROR read:", err)
		os.Exit(1)
	}
	fmt.Printf("REPLY %s", reply)
}
