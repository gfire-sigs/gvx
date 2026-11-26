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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

const (
	packetLinkChildEnv     = "GVX_TEST_PACKET_LINK_LOCKDOWN_CHILD"
	packetLinkChildAddrEnv = "GVX_TEST_PACKET_LINK_ADDR"
)

type closeCountingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *closeCountingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func TestConfigNormalizeNetModeLinkValidation(t *testing.T) {
	u1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u1.Close()
	u2, err := net.DialUDP("udp4", nil, u1.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer u2.Close()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing LinkConn", Config{NetworkMode: NetModeLink}},
		{"UDPConn rejected", Config{NetworkMode: NetModeLink, LinkConn: u2}},
		{"LinkMTU too small", Config{NetworkMode: NetModeLink, LinkConn: c1, LinkMTU: 67}},
		{"LinkMTU too large", Config{NetworkMode: NetModeLink, LinkConn: c1, LinkMTU: 65536}},
		{"LinkConn with NAT", Config{NetworkMode: NetModeNAT, LinkConn: c1}},
		{"LinkConn with None", Config{NetworkMode: NetModeNone, LinkConn: c1}},
		{"LinkMTU with NAT", Config{NetworkMode: NetModeNAT, LinkMTU: 1400}},
		{"IsolateLAN with Link", Config{NetworkMode: NetModeLink, LinkConn: c1, IsolateLAN: true}},
		{"Bandwidth with Link", Config{NetworkMode: NetModeLink, LinkConn: c1, NetworkBandwidth: netbackend.BandwidthRates{TXBPS: 1024}}},
		{"NetworkPolicy with Link", Config{NetworkMode: NetModeLink, LinkConn: c1, NetworkPolicy: &netbackend.NATPolicyConfig{}}},
		{"PortForwards with Link", Config{NetworkMode: NetModeLink, LinkConn: c1, PortForwards: []PortForward{{GuestPort: 80}}}},
		{"PublishAll with Link", Config{NetworkMode: NetModeLink, LinkConn: c1, PublishAll: true}},
		{"AutoPublishPorts with Link", Config{NetworkMode: NetModeLink, LinkConn: c1, AutoPublishPorts: true}},
		{"DynamicPorts with Link", Config{NetworkMode: NetModeLink, LinkConn: c1, DynamicPorts: true}},
		{"DynamicPortAddrs with Link", Config{NetworkMode: NetModeLink, LinkConn: c1, DynamicPortAddrs: []string{"127.0.0.1"}}},
		{"WireGuardConfigPath with Link", Config{NetworkMode: NetModeLink, LinkConn: c1, WireGuardConfigPath: "wg.conf"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if err := cfg.normalize(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("normalize() = %v, want ErrInvalidConfig", err)
			}
		})
	}

	// Valid config succeeds and sets expected lockdown options.
	valid := Config{NetworkMode: NetModeLink, LinkConn: c1, LinkMTU: 1420}
	if err := valid.normalize(); err != nil {
		t.Fatalf("valid normalize() failed: %v", err)
	}
	sb := &Sandbox{cfg: valid}
	opts := sb.lockdownOptions()
	if opts.AllowOutboundNet {
		t.Error("NetModeLink lockdownOptions().AllowOutboundNet = true, want false")
	}
	if !opts.PrewarmNetwork {
		t.Error("NetModeLink lockdownOptions().PrewarmNetwork = false, want true")
	}
	if len(opts.OutboundUDPPorts) != 0 {
		t.Errorf("NetModeLink lockdownOptions().OutboundUDPPorts = %v, want empty", opts.OutboundUDPPorts)
	}
}

func TestNewAndRestoreCloseLinkConnOnceOnFailure(t *testing.T) {
	t.Run("New normalize failure closes LinkConn once", func(t *testing.T) {
		raw1, raw2 := net.Pipe()
		defer raw2.Close()
		cc := &closeCountingConn{Conn: raw1}
		_, err := New(context.Background(), Config{
			NetworkMode: NetModeLink,
			LinkConn:    cc,
			LinkMTU:     10, // invalid
		})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New() err = %v, want ErrInvalidConfig", err)
		}
		if got := cc.closes.Load(); got != 1 {
			t.Errorf("LinkConn Close count = %d, want 1", got)
		}
	})

	t.Run("New post-normalize failure closes LinkConn once", func(t *testing.T) {
		raw1, raw2 := net.Pipe()
		defer raw2.Close()
		cc := &closeCountingConn{Conn: raw1}
		_, err := New(context.Background(), Config{
			NetworkMode:         NetModeLink,
			LinkConn:            cc,
			DisableHostLockdown: true,
			ServeMounts:         []ServeMount{{GuestPath: "/rpc", HostPath: t.TempDir()}}, // rejected by New
		})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New() err = %v, want ErrInvalidConfig", err)
		}
		if got := cc.closes.Load(); got != 1 {
			t.Errorf("LinkConn Close count = %d, want 1", got)
		}
	})

	t.Run("Restore early failure closes LinkConn once", func(t *testing.T) {
		raw1, raw2 := net.Pipe()
		defer raw2.Close()
		cc := &closeCountingConn{Conn: raw1}
		_, err := Restore(context.Background(), Config{
			NetworkMode: NetModeLink,
			LinkConn:    cc,
		}, RestoreOptions{}) // empty Dir
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Restore() err = %v, want ErrInvalidConfig", err)
		}
		if got := cc.closes.Load(); got != 1 {
			t.Errorf("LinkConn Close count = %d, want 1", got)
		}
	})

	t.Run("New post-transfer failure closes LinkConn once", func(t *testing.T) {
		blockingFile := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(blockingFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		raw1, raw2 := net.Pipe()
		defer raw2.Close()
		cc := &closeCountingConn{Conn: raw1}
		_, err := New(context.Background(), Config{
			NetworkMode:            NetModeLink,
			LinkConn:               cc,
			DisableHostLockdown:    true,
			AllowUnconfinedSystrap: true,
			CheckpointDir:          blockingFile,
		})
		if err == nil {
			t.Fatal("New() succeeded with regular file as CheckpointDir, want error")
		}
		if got := cc.closes.Load(); got != 1 {
			t.Errorf("LinkConn Close count = %d, want 1", got)
		}
		if errors.Is(err, ErrPlatformUnavailable) {
			t.Skipf("no execution platform available on host: %v", err)
		}
		if errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New() failed before LinkConn transfer: %v", err)
		}
	})

	t.Run("Restore post-transfer failure closes LinkConn once", func(t *testing.T) {
		opened, err := openPlatform(PlatformAuto, false, true)
		if errors.Is(err, ErrPlatformUnavailable) {
			t.Skipf("no execution platform available on host: %v", err)
		}
		if err != nil {
			t.Fatalf("openPlatform: %v", err)
		}
		platName := opened.name
		holes := platformAddrHoles(opened.plat)
		if closer, ok := opened.plat.(io.Closer); ok {
			if cerr := closer.Close(); cerr != nil {
				t.Fatalf("close probe platform: %v", cerr)
			}
		}

		bundleDir := t.TempDir()
		manifestBytes, err := json.Marshal(CheckpointManifest{
			Version:          CheckpointManifestVersion,
			GOOS:             runtime.GOOS,
			GOARCH:           runtime.GOARCH,
			Platform:         platName,
			Arch:             runtime.GOARCH,
			UserAddressHoles: holes,
			NetMode:          NetModeLink,
		})
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{
			checkpointManifestFileName:  manifestBytes,
			checkpointStateFileName:     {},
			checkpointPagesMetaFileName: {},
			checkpointPagesFileName:     {},
		} {
			if err := os.WriteFile(filepath.Join(bundleDir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		blockingFile := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(blockingFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}

		raw1, raw2 := net.Pipe()
		defer raw2.Close()
		cc := &closeCountingConn{Conn: raw1}
		_, err = Restore(context.Background(), Config{
			NetworkMode:            NetModeLink,
			LinkConn:               cc,
			DisableHostLockdown:    true,
			AllowUnconfinedSystrap: true,
			CheckpointDir:          blockingFile,
		}, RestoreOptions{Dir: bundleDir})
		if err == nil {
			t.Fatal("Restore() succeeded with regular file as CheckpointDir, want error")
		}
		if errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrCheckpointManifest) {
			t.Fatalf("Restore() failed before LinkConn transfer: %v", err)
		}
		if got := cc.closes.Load(); got != 1 {
			t.Errorf("LinkConn Close count = %d, want 1", got)
		}
	})
}

func TestPacketLinkTwoConcurrentSandboxesInProcess(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan error, 2)

	runOne := func(mtu uint32, msg string) {
		defer wg.Done()
		c1, c2 := net.Pipe()
		defer c2.Close()
		cfg := Config{NetworkMode: NetModeLink, LinkConn: c1, LinkMTU: mtu}
		if err := cfg.normalize(); err != nil {
			errs <- err
			return
		}
		sb := &Sandbox{cfg: cfg}
		if err := sb.initNetstack(); err != nil {
			errs <- err
			return
		}
		defer func() {
			if cerr := sb.Close(); cerr != nil {
				errs <- cerr
			}
		}()

		peerStop, err := runFramedEchoPeer(c2, mtu, "203.0.113.55", 9000)
		if err != nil {
			errs <- err
			return
		}
		defer peerStop()

		conn, err := gonet.DialTCP(sb.netStack, tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 55}),
			Port: 9000,
		}, ipv4.ProtocolNumber)
		if err != nil {
			errs <- err
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(msg)); err != nil {
			errs <- err
			return
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, got); err != nil {
			errs <- err
			return
		}
		if string(got) != msg {
			errs <- errors.New("echo mismatch: " + string(got))
			return
		}
	}

	wg.Add(2)
	go runOne(1500, "sandbox-alpha-packet-link")
	go runOne(4000, "sandbox-beta-packet-link")
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent PacketLink sandbox failed: %v", err)
	}
}

func TestPacketLinkWorksUnderHostLockdown(t *testing.T) {
	if os.Getenv(packetLinkChildEnv) == "1" {
		addr := os.Getenv(packetLinkChildAddrEnv)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("pre-lockdown dial %q: %v", addr, err)
		}
		cfg := Config{
			NetworkMode: NetModeLink,
			LinkConn:    conn,
		}
		if err := cfg.normalize(); err != nil {
			_ = conn.Close()
			t.Fatalf("normalize: %v", err)
		}
		sb := &Sandbox{cfg: cfg}
		if err := sb.initNetstack(); err != nil {
			t.Fatalf("initNetstack: %v", err)
		}
		defer func() {
			if cerr := sb.Close(); cerr != nil {
				t.Fatalf("Sandbox.Close: %v", cerr)
			}
		}()

		st, err := applyNetLinkTestLockdownOpts(sb.lockdownOptions())
		if err != nil {
			t.Fatalf("applyNetLinkTestLockdownOpts: %v", err)
		}
		installHostLockdownBridges()
		if !st.Applied || !st.SubprocessBlocked || !st.NetworkOutboundBlocked {
			t.Fatalf("lockdown status = %+v, want Applied && SubprocessBlocked && NetworkOutboundBlocked", st)
		}

		// Exchange real TCP traffic through eth0 over the pre-connected LinkConn
		// after hostlockdown has blocked all new outbound host sockets.
		tcpConn, err := gonet.DialTCP(sb.netStack, tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 99}),
			Port: 8081,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("DialTCP under hostlockdown: %v", err)
		}
		want := bytes.Repeat([]byte("locked-link-ok!"), 64)
		if _, err := tcpConn.Write(want); err != nil {
			_ = tcpConn.Close()
			t.Fatalf("Write under hostlockdown: %v", err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(tcpConn, got); err != nil {
			_ = tcpConn.Close()
			t.Fatalf("ReadFull under hostlockdown: %v", err)
		}
		_ = tcpConn.Close()
		if !bytes.Equal(got, want) {
			t.Fatalf("locked TCP echo mismatch")
		}
		return
	}

	// Host parent listens on loopback TCP and serves a strict framed L3 peer
	// Netstack for the locked-down child process.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	childDone := make(chan struct{})
	peerErrCh := make(chan error, 1)
	go func() {
		peerConn, err := ln.Accept()
		if err != nil {
			peerErrCh <- err
			return
		}
		stop, err := runFramedEchoPeer(peerConn, netbackend.DefaultPacketLinkMTU, "203.0.113.99", 8081)
		if err != nil {
			peerErrCh <- err
			return
		}
		defer stop()
		<-childDone
		peerErrCh <- nil
	}()

	exe, err := os.Executable()
	if err != nil {
		close(childDone)
		_ = ln.Close()
		<-peerErrCh
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.v", "-test.run=^TestPacketLinkWorksUnderHostLockdown$")
	cmd.Env = append(os.Environ(),
		packetLinkChildEnv+"=1",
		packetLinkChildAddrEnv+"="+ln.Addr().String(),
	)
	out, err := cmd.CombinedOutput()
	close(childDone)
	_ = ln.Close()
	peerErr := <-peerErrCh
	if err != nil {
		t.Fatalf("locked NetModeLink child failed: %v (peer err=%v)\n%s", err, peerErr, out)
	}
	if peerErr != nil {
		t.Fatalf("peer stack failed: %v", peerErr)
	}
}

// runFramedEchoPeer attaches a standards-compliant Netstack peer over peerConn
// using NewPacketLinkStack and serves TCP echo on peerIP:port.
func runFramedEchoPeer(peerConn net.Conn, mtu uint32, peerIP string, port uint16) (func(), error) {
	ip := netip.MustParseAddr(peerIP)
	st, pl, err := netbackend.NewPacketLinkStack(netbackend.PacketLinkConfig{
		Conn:      peerConn,
		MTU:       mtu,
		GuestIPv4: netip.PrefixFrom(ip, 24),
	})
	if err != nil {
		return nil, fmt.Errorf("peer NewPacketLinkStack: %w", err)
	}
	ln, err := gonet.ListenTCP(st, tcpip.FullAddress{
		Addr: tcpip.AddrFrom4(ip.As4()),
		Port: port,
	}, ipv4.ProtocolNumber)
	if err != nil {
		_ = pl.Close()
		return nil, fmt.Errorf("peer ListenTCP: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			_ = ln.Close()
			_ = pl.Close()
			wg.Wait()
		})
	}, nil
}
