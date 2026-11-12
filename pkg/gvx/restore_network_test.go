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
	"net"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

func TestRestoreNATClosesTheInitialGuestStack(t *testing.T) {
	oldStack, nf, err := netbackend.NewNATStack(netbackend.NATConfig{})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	t.Cleanup(func() { _ = nf.Close() })
	// A guest socket of the initial stack stands for the endpoints, timers,
	// and goroutines that Stack.Close ends.
	guestAddr := tcpip.FullAddress{NIC: netbackend.Eth0NICID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 15}), Port: 7000}
	ln, err := gonet.ListenTCP(oldStack, guestAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	acceptDone := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		acceptDone <- err
	}()
	restoredRaw, err := netbackend.NewLoopbackStack(netbackend.StackOptions{})
	if err != nil {
		t.Fatalf("NewLoopbackStack: %v", err)
	}
	t.Cleanup(restoredRaw.Close)

	sb := &Sandbox{cfg: Config{NetworkMode: NetModeNAT}, natForwarder: nf, netStack: oldStack}
	if err := (restoreNetworkArgs{sb: sb}).ConfigureNetwork(netstack.NewStack(restoredRaw, 1)); err != nil {
		t.Fatalf("ConfigureNetwork: %v", err)
	}
	if sb.netStack != restoredRaw {
		t.Fatal("the sandbox does not use the restored stack")
	}
	select {
	case err := <-acceptDone:
		if err == nil {
			t.Fatal("Accept on the initial guest stack returned a connection")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the initial guest stack still serves its sockets after the restore, want it closed")
	}
}

// closeCountingListener counts Close calls.
type closeCountingListener struct {
	net.Listener
	closed int
}

func (l *closeCountingListener) Close() error {
	l.closed++
	return l.Listener.Close()
}

func TestNewAndRestoreCloseTheCheckpointListenerOnEarlyFailure(t *testing.T) {
	newListener := func(t *testing.T) *closeCountingListener {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("loopback TCP is unavailable: %v", err)
		}
		return &closeCountingListener{Listener: ln}
	}

	t.Run("New with an invalid config", func(t *testing.T) {
		ln := newListener(t)
		defer ln.Listener.Close()
		_, err := New(context.Background(), Config{CheckpointListener: ln, NetworkMode: "no-such-mode"})
		if err == nil {
			t.Fatal("New succeeded with an invalid network mode")
		}
		if ln.closed == 0 {
			t.Fatal("New returned an error and left the checkpoint listener open")
		}
	})

	t.Run("Restore without a directory", func(t *testing.T) {
		ln := newListener(t)
		defer ln.Listener.Close()
		if _, err := Restore(context.Background(), Config{CheckpointListener: ln}, RestoreOptions{}); err == nil {
			t.Fatal("Restore succeeded without a directory")
		}
		if ln.closed == 0 {
			t.Fatal("Restore returned an error and left the checkpoint listener open")
		}
	})
}
