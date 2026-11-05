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
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

func newTunedNATStack(t *testing.T, mtu int) (*NATForwarder, func(tcpip.NICID) uint32, func(uint32) tcpip.Error) {
	t.Helper()
	tuned, err := tuning.Values{}.WithInt(tuning.NATMTU, mtu)
	if err != nil {
		t.Fatal(err)
	}
	s, fwd, err := NewNATStack(NATConfig{Tuning: tuned})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	t.Cleanup(func() { _ = fwd.Close(); s.Close() })
	nicMTU := func(id tcpip.NICID) uint32 {
		if id == hostNICID {
			return fwd.stack.NICInfo()[hostNICID].MTU
		}
		return s.NICInfo()[id].MTU
	}
	return fwd, nicMTU, func(m uint32) tcpip.Error { return s.SetNICMTU(Eth0NICID, m) }
}

func TestNATTunableSetsTheMTUOfBothEndsOfTheLink(t *testing.T) {
	_, nicMTU, _ := newTunedNATStack(t, 9000)
	if got := nicMTU(Eth0NICID); got != 9000 {
		t.Errorf("eth0 MTU = %d, want 9000", got)
	}
	if got := nicMTU(hostNICID); got != 9000 {
		t.Errorf("host NIC MTU = %d, want 9000", got)
	}
}

func TestSetNICMTUOfEth0FollowsTheLinuxRange(t *testing.T) {
	_, nicMTU, setMTU := newTunedNATStack(t, 1500)
	for _, bad := range []uint32{0, 67, 65536, 1 << 20} {
		if err := setMTU(bad); err == nil {
			t.Errorf("SetNICMTU(%d) succeeded, want an error", bad)
		}
	}
	if got := nicMTU(Eth0NICID); got != 1500 {
		t.Errorf("eth0 MTU = %d after refused changes, want 1500", got)
	}
	for _, good := range []uint32{68, 1400, 9000, 65535} {
		if err := setMTU(good); err != nil {
			t.Errorf("SetNICMTU(%d) = %v, want success", good, err)
			continue
		}
		if got, peer := nicMTU(Eth0NICID), nicMTU(hostNICID); got != good || peer != good {
			t.Errorf("after SetNICMTU(%d): eth0 MTU = %d, host NIC MTU = %d", good, got, peer)
		}
	}
}

// TestNATRelaysTCPAfterTheMTUChanges sends 1 MiB in both directions through the
// NAT after the guest sets a smaller and a larger MTU on eth0.
func TestNATRelaysTCPAfterTheMTUChanges(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	hostPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64<<10)

	for _, mtu := range []uint32{576, 1400, 9000, 65535} {
		t.Run(fmt.Sprintf("mtu%d", mtu), func(t *testing.T) {
			s, fwd, err := NewNATStack(NATConfig{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = fwd.Close(); s.Close() }()
			if err := s.SetNICMTU(Eth0NICID, mtu); err != nil {
				t.Fatalf("SetNICMTU(%d): %v", mtu, err)
			}
			conn, err := gonet.DialTCP(s, tcpip.FullAddress{NIC: Eth0NICID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}), Port: hostPort}, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			errc := make(chan error, 1)
			go func() {
				_, err := conn.Write(payload)
				errc <- err
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("read the echo: %v", err)
			}
			if err := <-errc; err != nil {
				t.Fatalf("write: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Error("the echo differs from the payload")
			}
		})
	}
}

// TestNATRelaysLargeUDPDatagrams sends datagrams that exceed 9216 bytes, the
// default send limit of a macOS socket, through the NAT. The guest stack
// fragments them to the MTU of eth0, and the host stack reassembles them.
func TestNATRelaysLargeUDPDatagrams(t *testing.T) {
	host := newUDPEndpoint(t)
	s, fwd, err := NewNATStack(NATConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fwd.Close(); s.Close() }()
	if err := s.SetNICMTU(Eth0NICID, 9000); err != nil {
		t.Fatal(err)
	}
	conn, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{NIC: Eth0NICID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}), Port: uint16(host.addr().Port)}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, size := range []int{1400, 8972, 20000, 60000} {
		msg := bytes.Repeat([]byte{byte(size)}, size)
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write %d bytes: %v", size, err)
		}
		buf := make([]byte, 65536)
		if err := host.sock.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
			t.Fatal(err)
		}
		n, from, err := host.sock.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("host read of %d bytes: %v", size, err)
		}
		if !bytes.Equal(buf[:n], msg) {
			t.Fatalf("host received %d bytes, want the %d sent", n, size)
		}
		widenUDPSend(host.sock)
		if _, err := host.sock.WriteToUDP(msg, from); err != nil {
			t.Fatalf("host reply of %d bytes: %v", size, err)
		}
		reply := make([]byte, 65536)
		rn, err := conn.Read(reply)
		if err != nil || !bytes.Equal(reply[:rn], msg) {
			t.Fatalf("guest read of the %d byte reply = %d bytes, %v", size, rn, err)
		}
	}
}
