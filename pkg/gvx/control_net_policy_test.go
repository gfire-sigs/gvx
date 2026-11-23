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

package gvx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

func TestControlNetDialPolicyGatesLoopbackFallback(t *testing.T) {
	const eth0Only = `{"egress":{"default":"deny"},"ingress":{"default":"deny","rules":[{"action":"allow","cidr":"127.0.0.1/32","guest_cidr":"10.0.2.15/32","protocol":"tcp","ports":"18080"}]}}`
	const loopbackOnly = `{"egress":{"default":"deny"},"ingress":{"default":"deny","rules":[{"action":"allow","cidr":"127.0.0.1/32","guest_cidr":"127.0.0.1/32","protocol":"tcp","ports":"18080"}]}}`
	policy, err := ParseNATPolicy(strings.NewReader(eth0Only))
	if err != nil {
		t.Fatal(err)
	}
	cacheDir, regURL, imgRef := buildControlTestImage(t)
	rs := startControlTestSandbox(t, Config{
		Name:            "net-dial-policy",
		OCIImage:        imgRef,
		OCICacheDir:     cacheDir,
		RegistryBaseURL: regURL,
		NetworkMode:     NetModeNAT,
		NetworkPolicy:   &policy,
	})
	rs.stdout.waitForSubstring(t, "ready-marker\n", 15*time.Second)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	rs.sb.mu.Lock()
	st := rs.sb.netStack
	rs.sb.mu.Unlock()
	ln, err := gonet.ListenTCP(st, tcpip.FullAddress{
		NIC:  netbackend.LoopbackNICID,
		Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
		Port: 18080,
	}, ipv4.ProtocolNumber)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		<-done
	})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		_, _ = io.Copy(conn, conn)
	}()

	open := func() *control.Stream {
		t.Helper()
		s, err := rs.client.OpenStream(ctx, control.MethodNetDial, control.NetDialRequest{GuestPort: 18080})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	replace := func(raw string) {
		t.Helper()
		if err := rs.client.Call(ctx, control.MethodNATPolicySet, control.NATPolicyState{Policy: json.RawMessage(raw)}, nil); err != nil {
			t.Fatalf("replace NAT policy: %v", err)
		}
	}
	denied := open()
	if err := denied.WaitResponse(ctx, nil); !control.IsCode(err, control.CodeForbiddenByPolicy) {
		t.Fatalf("dial with fallback denied = %v, want FORBIDDEN_BY_POLICY", err)
	}
	replace(loopbackOnly)
	allowed := open()
	var response control.NetDialResponse
	if err := allowed.WaitResponse(ctx, &response); err != nil || response.RemoteAddr != "127.0.0.1:18080" {
		t.Fatalf("dial with fallback allowed = %q, %v; want loopback", response.RemoteAddr, err)
	}
	if err := allowed.WriteData(ctx, control.ChannelGeneric, []byte("echo"), false); err != nil {
		t.Fatal(err)
	}
	var echo [4]byte
	if _, err := io.ReadFull(allowed.ChannelReader(ctx, control.ChannelGeneric), echo[:]); err != nil || string(echo[:]) != "echo" {
		t.Fatalf("echo = %q, %v; want echo", echo, err)
	}
	replace(eth0Only)
	if n, err := allowed.ReadData(ctx, control.ChannelGeneric, echo[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read from revoked tunnel = %d bytes, %v; want EOF", n, err)
	}
}
