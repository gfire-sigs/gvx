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

//go:build unix

package netbackend

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

func shortUnixSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gvxpl-")
	if err != nil {
		t.Fatalf("os.MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestPacketLinkUnixSockets(t *testing.T) {
	t.Run("AF_UNIX SOCK_STREAM accepted and transfers packets", func(t *testing.T) {
		sockPath := filepath.Join(shortUnixSocketDir(t), "s.sock")
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("net.Listen unix: %v", err)
		}
		defer ln.Close()

		type acceptRes struct {
			c   net.Conn
			err error
		}
		ch := make(chan acceptRes, 1)
		go func() {
			c, err := ln.Accept()
			ch <- acceptRes{c, err}
		}()

		guestConn, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("net.Dial unix: %v", err)
		}
		res := <-ch
		if res.err != nil {
			_ = guestConn.Close()
			t.Fatalf("Accept unix: %v", res.err)
		}
		peerConn := res.c

		st, pl, err := NewPacketLinkStack(PacketLinkConfig{Conn: guestConn})
		if err != nil {
			_ = peerConn.Close()
			t.Fatalf("NewPacketLinkStack unix stream: %v", err)
		}
		defer pl.Close()

		peer := newFramedPeerStack(t, peerConn, DefaultPacketLinkMTU, HostDNSIPv4)
		startPeerUDPEcho(t, peer.st, HostDNSIPv4, 53)

		u, err := gonet.DialUDP(st, nil, &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
			Port: 53,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("DialUDP over unix stream: %v", err)
		}
		defer u.Close()
		if _, err := u.Write([]byte("unix-stream-ok")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		buf := make([]byte, 32)
		n, err := u.Read(buf)
		if err != nil || string(buf[:n]) != "unix-stream-ok" {
			t.Fatalf("Read = %q, %v; want unix-stream-ok", buf[:n], err)
		}
	})

	t.Run("AF_UNIX SOCK_DGRAM rejected via SO_TYPE and closed", func(t *testing.T) {
		dir := shortUnixSocketDir(t)
		srvPath := filepath.Join(dir, "s.sock")
		cliPath := filepath.Join(dir, "c.sock")

		srv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: srvPath, Net: "unixgram"})
		if err != nil {
			t.Fatalf("ListenUnixgram: %v", err)
		}
		defer srv.Close()

		cli, err := net.DialUnix("unixgram", &net.UnixAddr{Name: cliPath, Net: "unixgram"}, &net.UnixAddr{Name: srvPath, Net: "unixgram"})
		if err != nil {
			t.Fatalf("DialUnix unixgram: %v", err)
		}

		_, _, err = NewPacketLinkStack(PacketLinkConfig{Conn: cli})
		if !errors.Is(err, ErrInvalidPacketLinkConfig) {
			t.Fatalf("err = %v, want ErrInvalidPacketLinkConfig", err)
		}
		if _, werr := cli.Write([]byte("x")); !errors.Is(werr, net.ErrClosed) {
			t.Errorf("cli.Write after rejected NewPacketLinkStack = %v, want net.ErrClosed", werr)
		}
	})
}
