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

// Command statprobe measures how an iptables rule with the statistic match
// splits new flows between two local listeners. The probe runs as root in a
// guest. Each flow reaches the listener that the NAT rules select, and that
// listener answers with one byte: 'A' for the first listener, 'B' for the
// second.
//
// Usage:
//
//	statprobe split ADDR TARGET_A TARGET_B N [tcp|udp [BASE_PORT]]
//
// The probe listens on TARGET_A and TARGET_B (HOST:PORT), opens N flows to
// ADDR one after the other, and prints one line:
//
//	RESULT a=<n> b=<n> order=<string>
//
// The order field lists the listener of each flow in the order of the flows.
// The probe prints it only when N is at most 60. A run with N above 60 uses 16
// concurrent workers, so the order of the flows is not defined. A failed flow
// adds a line "ERRORS <count> first: <reason>" and makes the exit code 1.
//
// Without BASE_PORT the kernel picks the source port of each flow. With
// BASE_PORT the flow number i (from 0) uses the source port BASE_PORT+i. The
// NAT state of a closed flow stays for up to two minutes and a new flow with
// the same addresses and ports reuses it, so a caller that runs the probe
// more than once in a sandbox gives each run its own range of ports.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// orderLimit is the largest N that keeps the flows sequential and prints
	// the order.
	orderLimit = 60
	// poolSize is the number of concurrent flows of a larger run.
	poolSize = 16
	// flowTimeout bounds one flow, so a dropped packet fails the run.
	flowTimeout = 10 * time.Second
)

func main() {
	if len(os.Args) < 6 || os.Args[1] != "split" {
		fmt.Fprintln(os.Stderr, "usage: statprobe split ADDR TARGET_A TARGET_B N [tcp|udp]")
		os.Exit(2)
	}
	addr, targetA, targetB := os.Args[2], os.Args[3], os.Args[4]
	n, err := strconv.Atoi(os.Args[5])
	if err != nil || n < 1 {
		fmt.Fprintf(os.Stderr, "statprobe: invalid flow count %q\n", os.Args[5])
		os.Exit(2)
	}
	network := "tcp"
	if len(os.Args) > 6 {
		network = os.Args[6]
	}
	if network != "tcp" && network != "udp" {
		fmt.Fprintf(os.Stderr, "statprobe: unknown protocol %q\n", network)
		os.Exit(2)
	}
	basePort := 0
	if len(os.Args) > 7 {
		basePort, err = strconv.Atoi(os.Args[7])
		if err != nil || basePort < 1 || basePort+n > 65535 {
			fmt.Fprintf(os.Stderr, "statprobe: invalid base port %q for %d flows\n", os.Args[7], n)
			os.Exit(2)
		}
	}

	stop, err := listen(network, targetA, targetB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "statprobe: %v\n", err)
		os.Exit(1)
	}
	defer stop()

	order, errs := runFlows(network, addr, n, basePort)
	a, b := strings.Count(string(order), "A"), strings.Count(string(order), "B")
	line := fmt.Sprintf("RESULT a=%d b=%d", a, b)
	if n <= orderLimit {
		line += " order=" + string(order)
	}
	fmt.Println(line)
	if len(errs) > 0 {
		fmt.Printf("ERRORS %d first: %v\n", len(errs), errs[0])
		stop()
		os.Exit(1)
	}
}

// listen starts a listener on each target. The listener on targetA answers
// 'A' and the listener on targetB answers 'B'. The returned function stops
// both listeners.
func listen(network, targetA, targetB string) (stop func(), err error) {
	var closers []io.Closer
	stop = func() {
		for _, c := range closers {
			_ = c.Close()
		}
		closers = nil
	}
	for _, t := range []struct {
		target string
		answer byte
	}{{targetA, 'A'}, {targetB, 'B'}} {
		if network == "tcp" {
			ln, lerr := net.Listen("tcp", t.target)
			if lerr != nil {
				stop()
				return nil, lerr
			}
			closers = append(closers, ln)
			go serveTCP(ln, t.answer)
			continue
		}
		pc, lerr := net.ListenPacket("udp", t.target)
		if lerr != nil {
			stop()
			return nil, lerr
		}
		closers = append(closers, pc)
		go serveUDP(pc, t.answer)
	}
	return stop, nil
}

// serveTCP answers each accepted connection with one byte and closes it. It
// returns when the listener closes.
func serveTCP(ln net.Listener, answer byte) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetWriteDeadline(time.Now().Add(flowTimeout))
			_, _ = c.Write([]byte{answer})
		}()
	}
}

// serveUDP answers each datagram with one byte to its sender. It returns when
// the socket closes.
func serveUDP(pc net.PacketConn, answer byte) {
	buf := make([]byte, 16)
	for {
		_, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo([]byte{answer}, from)
	}
}

// runFlows opens n flows to addr and returns the answer bytes in flow order
// and the errors of the failed flows. A failed flow leaves '?' in its slot.
// A positive basePort gives flow i the source port basePort+i.
func runFlows(network, addr string, n, basePort int) ([]byte, []error) {
	order := make([]byte, n)
	workers := 1
	if n > orderLimit {
		workers = poolSize
	}
	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
		next = make(chan int)
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				srcPort := 0
				if basePort > 0 {
					srcPort = basePort + i
				}
				answer, err := oneFlow(network, addr, srcPort)
				mu.Lock()
				if err != nil {
					order[i] = '?'
					errs = append(errs, fmt.Errorf("flow %d: %w", i+1, err))
				} else {
					order[i] = answer
				}
				mu.Unlock()
			}
		}()
	}
	for i := range n {
		next <- i
	}
	close(next)
	wg.Wait()
	return order, errs
}

// oneFlow opens one connection or one UDP socket to addr and returns the byte
// that the selected listener answers. A non-zero srcPort sets the source port.
func oneFlow(network, addr string, srcPort int) (byte, error) {
	d := net.Dialer{Timeout: flowTimeout}
	if srcPort != 0 {
		if network == "tcp" {
			d.LocalAddr = &net.TCPAddr{Port: srcPort}
		} else {
			d.LocalAddr = &net.UDPAddr{Port: srcPort}
		}
	}
	c, err := d.Dial(network, addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(flowTimeout)); err != nil {
		return 0, err
	}
	if network == "udp" {
		if _, err := c.Write([]byte{'?'}); err != nil {
			return 0, err
		}
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}
