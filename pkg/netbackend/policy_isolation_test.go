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

package netbackend

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

func TestNATPolicyInstancesKeepIndependentRelays(t *testing.T) {
	ctx := testContext(t)
	const base = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
	compile := func(input string, tx PolicyLimit) *CompiledPolicy {
		t.Helper()
		program, err := CompilePolicy(PolicyConfig{RulesV4: base + input + "COMMIT\n", RulesV6: base + "COMMIT\n", TX: tx})
		if err != nil {
			t.Fatalf("compile policy: %v", err)
		}
		return program
	}

	start := func(limit PolicyLimit) (*NATPolicy, net.Conn, <-chan []string) {
		t.Helper()
		listen, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		end := make(chan []string, 1)
		go func() {
			var received []string
			defer func() { end <- received; close(end) }()
			conn, err := listen.AcceptTCP()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(testTimeout))
			lines := bufio.NewScanner(conn)
			for lines.Scan() {
				line := lines.Text()
				received = append(received, line)
				if _, err := io.WriteString(conn, line+"\n"); err != nil {
					return
				}
			}
		}()
		t.Cleanup(func() { _ = listen.Close(); <-end })
		p := NewNATPolicy(compile("", limit), netip.AddrPort{})
		t.Cleanup(func() { p.Close() })
		s, nat, err := NewNATStack(NATConfig{Policy: p})
		if err != nil {
			t.Fatalf("create protected NAT stack: %v", err)
		}
		t.Cleanup(func() { _ = nat.Close(); s.Close() })
		dest := fullAddr(netip.MustParseAddr(HostGatewayIPv4), uint16(listen.Addr().(*net.TCPAddr).Port))
		conn, err := gonet.DialContextTCP(ctx, s, dest, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("connect through protected NAT: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return p, conn, end
	}
	exchange := func(conn net.Conn, payload string) {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, payload); err != nil {
			t.Fatal(err)
		}
		echo := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != payload {
			t.Fatalf("echo = %q, %v; want %q", echo, err, payload)
		}
	}

	a, aConn, aReceived := start(PolicyLimit{})
	_, bConn, _ := start(PolicyLimit{RateBPS: 10_000_000, BurstBytes: 131072, QueueBytes: 262144})
	exchange(aConn, "alpha before\n")
	exchange(bConn, "beta before\n")

	// Keep the guest packet leg open. Only A's actual host tuple denies input.
	denyHost := compile("-A INPUT -d 127.0.0.1/32 -j DROP\n", PolicyLimit{RateBPS: 1, BurstBytes: 131072, QueueBytes: 262144})
	if err := a.Commit(denyHost, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	exchange(bConn, "beta after\n")
	_ = aConn.SetDeadline(time.Now().Add(testTimeout))
	_, err := io.WriteString(aConn, "alpha after\n")
	if err == nil {
		var first [1]byte
		_, err = aConn.Read(first[:])
	}
	var netErr net.Error
	if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("A's denied relay continued: %v", err)
	}
	select {
	case got := <-aReceived:
		if strings.Join(got, ",") != "alpha before" {
			t.Fatalf("A's host server received %q after cutover", got)
		}
	case <-ctx.Done():
		t.Fatal("A's host connection did not close")
	}
}
