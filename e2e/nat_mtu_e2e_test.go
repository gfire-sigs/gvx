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

//go:build darwin || windows || linux

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
)

// mustTune builds Values from key and value pairs, as rungv --tune does.
func mustTune(t *testing.T, pairs map[string]string) tuning.Values {
	t.Helper()
	v, err := tuning.Parse(pairs)
	if err != nil {
		t.Fatalf("tuning.Parse(%v): %v", pairs, err)
	}
	return v
}

// TestE2ENATLinkMTUTunable sets net.nat.mtu to 9000. eth0 then has MTU 9000
// in netlink and in /sys/class/net/eth0/mtu, and the tunnels that flannel
// derives from it get 8950 for vxlan and 8920 for WireGuard.
func TestE2ENATLinkMTUTunable(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
			cfg.NetworkMode = gvx.NetModeNAT
			cfg.Tuning = mustTune(t, map[string]string{"net.nat.mtu": "9000"})
		}, "natmtu", "9000")
		requireNodeChecks(t, code, out,
			"eth0-has-the-expected-mtu-and-lo-keeps-65536", "sysfs-shows-the-mtu-of-eth0",
			"vxlan-over-eth0-gets-mtu-minus-50",
			"wireguard-over-eth0-with-the-formula-of-flannel-gets-mtu-minus-80")
	})
}

// TestE2ENATLinkMTUChangeKeepsTCPWorking changes the MTU of eth0 from the
// guest with RTM_SETLINK, as "ip link set dev eth0 mtu N" does, and with the
// ioctl SIOCSIFMTU, as the busybox tools do. After each change the guest reads
// the new MTU in netlink and sysfs and moves 1 MiB in each direction through
// the NAT. The test also checks the Linux range, the capability, the MTU of
// each end of a veth pair, and the loss of IPv6 below an MTU of 1280.
func TestE2ENATLinkMTUChangeKeepsTCPWorking(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen on the host: %v", err)
		}
		defer ln.Close()
		go serveThroughput(ln)
		addr := net.JoinHostPort("10.0.2.2", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
		code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
			cfg.NetworkMode = gvx.NetModeNAT
		}, "mtuset", addr)
		requireNodeChecks(t, code, out,
			"tcp-transfer-at-mtu-1500",
			"set-eth0-mtu-1400", "tcp-transfer-at-mtu-1400",
			"set-eth0-mtu-576", "tcp-transfer-at-mtu-576",
			"set-eth0-mtu-9000", "tcp-transfer-at-mtu-9000",
			"set-eth0-mtu-65535", "tcp-transfer-at-mtu-65535",
			"eth0-refuses-mtu-below-68", "eth0-refuses-mtu-above-65535", "eth0-accepts-the-minimum-68",
			"veth-follows-the-same-range", "veth-ends-have-their-own-mtu",
			"siocsifmtu-sets-eth0-and-siocgifmtu-reads-it", "siocsifmtu-sets-a-veth-end",
			"siocsifmtu-follows-the-linux-range", "siocsifmtu-needs-cap-net-admin",
			"tcp-transfer-after-siocsifmtu", "ipv6-stops-below-1280-and-returns-at-1280")
	})
}

// TestE2ENATLinkMTUWithIPTool runs the unmodified "ip" of iproute2 in Alpine. The test
// sets net.nat.mtu to 9000, reads the MTU with "ip link" and sysfs, lowers it
// with "ip link set dev eth0 mtu 1400", and sends 1 MiB through the NAT to a
// listener on the host. The listener checks the hash of the data.
func TestE2ENATLinkMTUWithIPTool(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on the host: %v", err)
	}
	defer ln.Close()
	const size = 1 << 20
	sums := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				h := sha256.New()
				_ = conn.SetReadDeadline(time.Now().Add(time.Minute))
				if _, err := io.CopyN(h, conn, size); err == nil {
					sums <- hex.EncodeToString(h.Sum(nil))
				}
			}()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	script := `set -e
apk add --no-cache iproute2 >/dev/null
echo SYSFS-BEFORE $(cat /sys/class/net/eth0/mtu)
echo LINK-BEFORE $(ip -o link show dev eth0)
ip link set dev eth0 mtu 1400
echo SYSFS-AFTER $(cat /sys/class/net/eth0/mtu)
echo LINK-AFTER $(ip -o link show dev eth0)
if ip link set dev eth0 mtu 67 2>/tmp/err; then echo LOW-ACCEPTED; else echo LOW-REFUSED $(cat /tmp/err); fi
if ip link set dev eth0 mtu 65536 2>/tmp/err; then echo HIGH-ACCEPTED; else echo HIGH-REFUSED $(cat /tmp/err); fi
head -c 1048576 /dev/urandom > /tmp/data
echo SUM-SENT $(sha256sum < /tmp/data | cut -d' ' -f1)
nc -w 10 10.0.2.2 ` + port + ` < /tmp/data
echo SENT
`
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script}, net: gvx.NetModeNAT, netRaw: true,
				tuning: mustTune(t, map[string]string{"net.nat.mtu": "9000"}),
			})
			t.Log(out)
			requireContains(t, "MTU before the change", out, "SYSFS-BEFORE 9000\n", "mtu 9000")
			requireContains(t, "MTU after the change", out, "SYSFS-AFTER 1400\n", "mtu 1400")
			requireContains(t, "range checks", out, "LOW-REFUSED RTNETLINK answers: Invalid argument\n", "HIGH-REFUSED RTNETLINK answers: Invalid argument\n")
			var sent string
			for _, l := range strings.Split(out, "\n") {
				if rest, ok := strings.CutPrefix(l, "SUM-SENT "); ok {
					sent = rest
				}
			}
			select {
			case got := <-sums:
				if got != sent || len(sent) != 64 {
					t.Errorf("the host received sha256 %q, the guest sent %q", got, sent)
				}
			case <-time.After(time.Minute):
				t.Fatal("the host received no data")
			}
		})
	}
}

// TestE2ENATLinkMTUWithBusybox runs the busybox "ifconfig" and the busybox "ip"
// of Alpine, which change the MTU with the ioctl SIOCSIFMTU and read nothing
// through netlink. The test checks the new value in sysfs, the range, and a
// transfer of 1 MiB through the NAT. The host listener checks the hash.
func TestE2ENATLinkMTUWithBusybox(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on the host: %v", err)
	}
	defer ln.Close()
	const size = 1 << 20
	sums := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				h := sha256.New()
				_ = conn.SetReadDeadline(time.Now().Add(time.Minute))
				if _, err := io.CopyN(h, conn, size); err == nil {
					sums <- hex.EncodeToString(h.Sum(nil))
				}
			}()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	script := `ip() { busybox ip "$@"; }
echo IFCONFIG-BEFORE $(ifconfig eth0 | grep -o 'MTU:[0-9]*')
ifconfig eth0 mtu 1400
echo SYSFS-IFCONFIG $(cat /sys/class/net/eth0/mtu)
echo IFCONFIG-AFTER $(ifconfig eth0 | grep -o 'MTU:[0-9]*')
ip link set dev eth0 mtu 1300
echo SYSFS-IP $(cat /sys/class/net/eth0/mtu)
if ifconfig eth0 mtu 67 2>/tmp/err; then echo LOW-ACCEPTED; else echo LOW-REFUSED $(cat /tmp/err); fi
if ip link set dev eth0 mtu 65536 2>/tmp/err; then echo HIGH-ACCEPTED; else echo HIGH-REFUSED $(cat /tmp/err); fi
echo SYSFS-AFTER-REFUSED $(cat /sys/class/net/eth0/mtu)
head -c 1048576 /dev/urandom > /tmp/data
echo SUM-SENT $(sha256sum < /tmp/data | cut -d' ' -f1)
nc -w 10 10.0.2.2 ` + port + ` < /tmp/data
echo SENT
`
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script}, net: gvx.NetModeNAT, netRaw: true,
			})
			t.Log(out)
			requireContains(t, "MTU before the change", out, "IFCONFIG-BEFORE MTU:1500\n")
			requireContains(t, "ifconfig", out, "SYSFS-IFCONFIG 1400\n", "IFCONFIG-AFTER MTU:1400\n")
			requireContains(t, "ip", out, "SYSFS-IP 1300\n")
			requireContains(t, "range checks", out, "LOW-REFUSED", "HIGH-REFUSED", "Invalid argument", "SYSFS-AFTER-REFUSED 1300\n")
			var sent string
			for _, l := range strings.Split(out, "\n") {
				if rest, ok := strings.CutPrefix(l, "SUM-SENT "); ok {
					sent = rest
				}
			}
			select {
			case got := <-sums:
				if got != sent || len(sent) != 64 {
					t.Errorf("the host received sha256 %q, the guest sent %q", got, sent)
				}
			case <-time.After(time.Minute):
				t.Fatal("the host received no data")
			}
		})
	}
}

// TestE2ERungvTuneSetsTheMTUOfEth0 runs the real rungv binary with the flags
// --tune and --tune-file. The guest reads the MTU of eth0 in netlink and in
// /sys/class/net/eth0/mtu. A --tune flag wins over the file.
func TestE2ERungvTuneSetsTheMTUOfEth0(t *testing.T) {
	rungv := toolPath(t, rungvPkg)
	probe := acceptprog.BuildNodeProbe(t, runtime.GOARCH)
	file := filepath.Join(t.TempDir(), "tune.json")
	if err := os.WriteFile(file, []byte(`{"net.nat.mtu": 1400}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		mtu  string
	}{
		{"flag", []string{"--tune", "net.nat.mtu=9000"}, "9000"},
		{"file", []string{"--tune-file", file}, "1400"},
		{"flag wins over the file", []string{"--tune-file", file, "--tune", "net.nat.mtu=9000"}, "9000"},
	} {
		for _, b := range fixedAddressBackends() {
			t.Run(tc.name+"/"+b.name, func(t *testing.T) {
				requireFixedAddressBackend(t, b)
				args := append([]string{"run", "-lockdown=false", "-platform=" + string(b.plat), "-net=nat", "-cache-dir=" + t.TempDir()}, tc.args...)
				args = append(args, "-bin="+probe, "--", "/bin/app", "natmtu", tc.mtu)
				stdout, stderr, code := runTool(t, rungv, args...)
				requireNodeChecks(t, code, stdout, "eth0-has-the-expected-mtu-and-lo-keeps-65536", "sysfs-shows-the-mtu-of-eth0")
				if code != 0 {
					t.Logf("stderr: %s", stderr)
				}
			})
		}
	}
	t.Run("a bad value is a usage error", func(t *testing.T) {
		_, stderr, code := runTool(t, rungv, "run", "-lockdown=false", "-net=nat", "--tune", "net.nat.mtu=67", "-bin="+probe, "--", "/bin/app", "natmtu")
		if code != 2 || !strings.Contains(stderr, "net.nat.mtu") || !strings.Contains(stderr, "68 to 65535") {
			t.Errorf("rungv run --tune net.nat.mtu=67 = (code %d, stderr %q), want code 2 and the key with its range", code, stderr)
		}
	})
	t.Run("tune list prints the registry", func(t *testing.T) {
		stdout, _, code := runTool(t, rungv, "tune", "list")
		if code != 0 || !strings.Contains(stdout, "net.nat.mtu") || !strings.Contains(stdout, "memory.cgroup.idle_poll_interval") {
			t.Errorf("rungv tune list = (code %d, stdout %q)", code, stdout)
		}
	})
}

// TestE2ERungvTuneMTUReadWithCat runs the Alpine image through rungv with
// --tune net.nat.mtu=9000 and reads the MTU with cat.
func TestE2ERungvTuneMTUReadWithCat(t *testing.T) {
	requireRegistry(t)
	rungv := toolPath(t, rungvPkg)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			stdout, stderr, code := runTool(t, rungv, "run", "-lockdown=false", "-platform="+string(b.plat), "-net=nat",
				"-cache-dir="+sharedCacheDir(t), "--tune", "net.nat.mtu=9000", "-image=alpine:3.20", "--", "cat", "/sys/class/net/eth0/mtu")
			if code != 0 || stdout != "9000\n" {
				t.Errorf("cat /sys/class/net/eth0/mtu = (code %d, stdout %q, stderr %q), want 9000", code, stdout, stderr)
			}
		})
	}
}
