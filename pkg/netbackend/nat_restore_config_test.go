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
	"context"
	"io"
	"net"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// saveAndRestoreStack saves orig with the real state encoder and loads it
// again, as Sandbox.Checkpoint and gvx.Restore do.
func saveAndRestoreStack(t *testing.T, orig *stack.Stack) *stack.Stack {
	t.Helper()
	saved := savedStackEndpoints{Stack: orig}
	orig.Pause()
	var buf bytes.Buffer
	_, err := state.Save(context.Background(), &buf, &saved)
	orig.Resume()
	if err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	var restored savedStackEndpoints
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	t.Cleanup(restored.Stack.Destroy)
	return restored.Stack
}

func TestNATAttachRestoredStackReappliesEth0Config(t *testing.T) {
	origStack, nf, err := NewNATStack(NATConfig{})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	defer func() {
		_ = nf.Close()
		origStack.Destroy()
	}()

	extra := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 0, 2, 77}), PrefixLen: 24},
	}
	if err := origStack.AddProtocolAddress(Eth0NICID, extra, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	const mtu = 1400
	if err := origStack.SetNICMTU(Eth0NICID, mtu); err != nil {
		t.Fatalf("SetNICMTU: %s", err)
	}
	extraRoute := tcpip.Route{
		Destination: mustSubnet(t, [4]byte{198, 51, 100, 0}, 24),
		Gateway:     tcpip.AddrFrom4([4]byte{10, 0, 2, 2}),
		NIC:         Eth0NICID,
	}
	origStack.AddRoute(extraRoute)

	// A saved Netstack holds no NIC settings, so the checkpoint records them
	// from the live stack, as Sandbox.Checkpoint does.
	snap, ok := SnapshotEth0Config(origStack)
	if !ok {
		t.Fatal("SnapshotEth0Config found no eth0")
	}
	restored := saveAndRestoreStack(t, origStack)
	if len(restored.NICInfo()) != 0 {
		t.Fatalf("a restored Netstack holds NICs %v before the attach, the premise of the snapshot is wrong", restored.NICInfo())
	}
	if err := nf.AttachRestoredStackWithConfig(restored, &snap); err != nil {
		t.Fatalf("AttachRestoredStackWithConfig: %v", err)
	}

	info := restored.NICInfo()[Eth0NICID]
	var haveDefault, haveExtra bool
	for _, pa := range info.ProtocolAddresses {
		switch pa.AddressWithPrefix.Address {
		case tcpip.AddrFrom4([4]byte{10, 0, 2, 15}):
			haveDefault = true
		case extra.AddressWithPrefix.Address:
			haveExtra = true
		}
	}
	if !haveDefault || !haveExtra {
		t.Errorf("eth0 addresses after restore = %v, want 10.0.2.15 and 10.0.2.77", info.ProtocolAddresses)
	}
	if info.MTU != mtu {
		t.Errorf("eth0 MTU after restore = %d, want %d", info.MTU, mtu)
	}
	var haveRoute, haveDefaultRoute bool
	for _, r := range restored.GetRouteTable() {
		if r.Destination == extraRoute.Destination && r.NIC == Eth0NICID {
			haveRoute = true
		}
		if r.Destination.Equal(mustSubnet(t, [4]byte{}, 0)) && r.NIC == Eth0NICID {
			haveDefaultRoute = true
		}
	}
	if !haveRoute || !haveDefaultRoute {
		t.Errorf("routes after restore = %v, want the guest route and the default route", restored.GetRouteTable())
	}

	// The restored stack still reaches the host through the NAT.
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	go func() {
		c, err := host.Accept()
		if err == nil {
			_, _ = io.Copy(c, c)
			_ = c.Close()
		}
	}()
	gw := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}), Port: uint16(host.Addr().(*net.TCPAddr).Port)}
	c, err := gonet.DialTCP(restored, gw, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial the host after restore: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(testTimeout))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo after restore = (%q, %v), want ping", buf, err)
	}
}

func mustSubnet(t *testing.T, addr [4]byte, prefix int) tcpip.Subnet {
	t.Helper()
	a := tcpip.AddrFrom4(addr)
	sub, err := tcpip.NewSubnet(a, tcpip.MaskFromBytes(prefixMask(prefix)))
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

func prefixMask(prefix int) []byte {
	m := make([]byte, 4)
	for i := range prefix {
		m[i/8] |= 0x80 >> (i % 8)
	}
	return m
}
