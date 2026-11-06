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
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// wgKeys is a WireGuard key pair in the base64 form of the "wg" tool.
type wgKeys struct{ private, public string }

// newWGKeys returns a key pair. The private key is clamped, as the output of
// "wg genkey" is.
func newWGKeys(t *testing.T) wgKeys {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	priv := k.Bytes()
	priv[0] &= 248
	priv[31] = priv[31]&127 | 64
	if k, err = ecdh.X25519().NewPrivateKey(priv); err != nil {
		t.Fatalf("load X25519 key: %v", err)
	}
	return wgKeys{
		private: base64.StdEncoding.EncodeToString(priv),
		public:  base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()),
	}
}

// runningGuest is a sandbox whose guest runs in the background. Its output
// goes to one transcript, and closing stdin ends a guest that waits for input.
type runningGuest struct {
	sb       *gvx.Sandbox
	out      *outputLog
	stdin    *io.PipeWriter
	finished chan struct{}
	res      guestResult
	// stop cancels the Run of the guest. The cleanup of the test calls it
	// too, and a second call has no effect.
	stop context.CancelFunc
}

// startGuest creates the sandbox of spec and runs it in the background. The
// cleanup of the test ends the guest and closes the sandbox.
func startGuest(t *testing.T, ctx context.Context, spec guestSpec) *runningGuest {
	t.Helper()
	g := &runningGuest{out: newOutputLog(), finished: make(chan struct{})}
	stdinR, stdinW := io.Pipe()
	g.stdin = stdinW
	spec.stdin = stdinR
	sb, err := gvx.New(ctx, spec.config(sharedCacheDir(t), g.out, g.out))
	if err != nil {
		t.Fatalf("gvx.New(%s, %s) failed: %v", spec.plat, spec.image, err)
	}
	g.sb = sb
	runCtx, stop := context.WithCancel(ctx)
	g.stop = stop
	go func() {
		defer close(g.finished)
		g.res.code, g.res.err = sb.Run(runCtx)
	}()
	t.Cleanup(func() {
		stdinW.Close()
		stop()
		<-g.finished
		if t.Failed() {
			t.Logf("guest output:\n%s", g.out.String())
		}
		if err := sb.Close(); err != nil {
			t.Errorf("Close(%s) failed: %v", spec.image, err)
		}
	})
	return g
}

// wait blocks until the transcript holds marker and returns the rest of the
// line of the marker.
func (g *runningGuest) wait(t *testing.T, marker string, timeout time.Duration) string {
	t.Helper()
	end := g.out.waitFor(t, 0, marker, timeout, g.finished)
	line, _, _ := strings.Cut(g.out.String()[end:], "\n")
	return strings.TrimSpace(line)
}

// wgToolsSetup installs the tools and writes the key file /tmp/key. Every
// two-sandbox script starts with it.
const wgToolsSetup = `set -e
apk add --no-cache wireguard-tools iproute2 >/dev/null
umask 077
echo "$WG_KEY" > /tmp/key
`

// TestE2EWireGuardA12ToolConfiguration checks the configuration round trip
// with the unmodified tools of Alpine: "wg set" configures a link that "ip
// link add" created, "wg show dump" prints what the test set, and "wg-quick"
// brings a link up from a configuration file and takes it down again.
func TestE2EWireGuardA12ToolConfiguration(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			script := `set -e
apk add --no-cache wireguard-tools wireguard-tools-wg-quick iproute2 bash >/dev/null
umask 077
wg genkey > /tmp/priv
wg pubkey < /tmp/priv > /tmp/pub
wg genkey | wg pubkey > /tmp/peerpub
wg genpsk > /tmp/psk
ip link add wg0 type wireguard
echo LINK $(ip -d link show wg0 | tr '\n' ' ')
wg set wg0 private-key /tmp/priv listen-port 51830 fwmark 0x1234 \
	peer $(cat /tmp/peerpub) preshared-key /tmp/psk endpoint 192.0.2.7:51820 \
	persistent-keepalive 25 allowed-ips 10.50.0.0/24,fd00:50::/64
echo PRIV $(cat /tmp/priv)
echo PUB $(cat /tmp/pub)
echo PEERPUB $(cat /tmp/peerpub)
echo PSK $(cat /tmp/psk)
wg show wg0 dump | sed 's/^/DUMP1 /'
wg show wg0 | sed 's/^/SHOW /'
mkdir -p /etc/wireguard
cat > /etc/wireguard/wgq.conf <<EOF
[Interface]
Address = 10.60.0.1/24
PrivateKey = $(cat /tmp/priv)
ListenPort = 51831
MTU = 1380
[Peer]
PublicKey = $(cat /tmp/peerpub)
PresharedKey = $(cat /tmp/psk)
AllowedIPs = 10.60.0.2/32, 192.168.60.0/24
Endpoint = 192.0.2.8:51820
PersistentKeepalive = 25
EOF
wg-quick up wgq
wg show wgq dump | sed 's/^/DUMP2 /'
echo LINK2 $(ip link show wgq | head -1)
echo ADDR $(ip -o -4 addr show wgq)
echo ROUTES $(ip -4 route show dev wgq | tr '\n' ';')
wg-quick down wgq
if ip link show wgq >/dev/null 2>&1; then echo WGQ-STILL-THERE; else echo WGQ-GONE; fi
wg set wg0 peer $(cat /tmp/peerpub) remove
wg show wg0 peers | wc -l | sed 's/^/PEERS-AFTER-REMOVE /'
ip link del wg0
if ip link show wg0 >/dev/null 2>&1; then echo WG0-STILL-THERE; else echo WG0-GONE; fi
`
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script}, net: gvx.NetModeNAT, netRaw: true,
			})
			field := func(name string) string {
				m := regexp.MustCompile(`(?m)^` + name + ` (.*)$`).FindStringSubmatch(out)
				if m == nil {
					t.Fatalf("output lacks %s; full output:\n%s", name, out)
				}
				return m[1]
			}
			priv, pub, peer, psk := field("PRIV"), field("PUB"), field("PEERPUB"), field("PSK")
			requireContains(t, "ip link show", field("LINK"), "mtu 1420", "wireguard")
			// The dump holds the device row, and then one row for each peer.
			dump := func(prefix string) [][]string {
				var rows [][]string
				for _, l := range strings.Split(out, "\n") {
					if rest, ok := strings.CutPrefix(l, prefix+" "); ok {
						rows = append(rows, strings.Split(rest, "\t"))
					}
				}
				return rows
			}
			check := func(name string, rows [][]string, port, mark, endpoint, allowed string) {
				if len(rows) != 2 || len(rows[0]) != 4 || len(rows[1]) != 8 {
					t.Fatalf("%s has the rows %q, want a device row and one peer row", name, rows)
				}
				dev, p := rows[0], rows[1]
				if dev[0] != priv || dev[1] != pub || dev[2] != port || dev[3] != mark {
					t.Errorf("%s device row = %q, want %s %s %s %s", name, dev, priv, pub, port, mark)
				}
				if p[0] != peer || p[1] != psk || p[2] != endpoint || p[3] != allowed || p[4] != "0" || p[5] != "0" || p[7] != "25" {
					t.Errorf("%s peer row = %q, want %s %s %s %s 0 0 any 25", name, p, peer, psk, endpoint, allowed)
				}
			}
			check("wg set", dump("DUMP1"), "51830", "0x1234", "192.0.2.7:51820", "10.50.0.0/24,fd00:50::/64")
			check("wg-quick", dump("DUMP2"), "51831", "off", "192.0.2.8:51820", "10.60.0.2/32,192.168.60.0/24")
			requireContains(t, "wg show", out, "SHOW interface: wg0", "SHOW   listening port: 51830", "SHOW   fwmark: 0x1234",
				"SHOW   endpoint: 192.0.2.7:51820", "SHOW   persistent keepalive: every 25 seconds",
				"SHOW   preshared key: (hidden)")
			requireContains(t, "wg-quick state", field("LINK2")+"\n"+field("ADDR")+"\n"+field("ROUTES")+"\n", "mtu 1380", "10.60.0.1/24", "10.60.0.0/24", "192.168.60.0/24")
			requireContains(t, "wg-quick down", out, "WGQ-GONE\n", "PEERS-AFTER-REMOVE 0\n", "WG0-GONE\n")
		})
	}
}

// wgTwoSandboxes starts sandbox A with the published UDP port 51820, and
// sandbox B after A is ready. Each guest first runs wgToolsSetup, then its
// script, with WG_KEY, WG_PUB_PEER, and for B WG_HOST_PORT set. B reaches A
// through the host gateway 10.0.2.2 and the host port of A. The scripts print
// the markers that the tests wait for.
func wgTwoSandboxes(t *testing.T, b gateBackend, aScript, bScript string) (a, bg *runningGuest) {
	t.Helper()
	if b.plat == gvx.PlatformWHPX {
		t.Skip("the whpx backend cannot hold two running sandboxes in one process")
	}
	requireFixedAddressBackend(t, b)
	requireRegistry(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	ka, kb := newWGKeys(t), newWGKeys(t)

	a = startGuest(t, ctx, guestSpec{
		plat: b.plat, image: "alpine:3.20", net: gvx.NetModeNAT, netRaw: true,
		forwards: []gvx.PortForward{{HostPort: 0, GuestPort: 51820, Protocol: "udp", BindAddress: "127.0.0.1"}},
		envv:     []string{"WG_KEY=" + ka.private, "WG_PUB_PEER=" + kb.public},
		argv:     []string{"sh", "-c", wgToolsSetup + aScript},
	})
	hostPort := a.sb.BoundPort(0)
	if hostPort == 0 {
		t.Fatal("BoundPort(0) = 0, want the host port of the published UDP port")
	}
	a.wait(t, "A-READY", 3*time.Minute)

	bg = startGuest(t, ctx, guestSpec{
		plat: b.plat, image: "alpine:3.20", net: gvx.NetModeNAT, netRaw: true,
		envv: []string{"WG_KEY=" + kb.private, "WG_PUB_PEER=" + ka.public, "WG_HOST_PORT=" + strconv.Itoa(hostPort)},
		argv: []string{"sh", "-c", wgToolsSetup + bScript},
	})
	return a, bg
}

// TestE2EWireGuardA12TwoSandboxesPublishedPort links two sandboxes of one
// host. A publishes UDP port 51820 and has no endpoint for B. B pings A
// through the gateway 10.0.2.2, then sends 256 KiB over TCP, and A learns the
// endpoint of B from the handshake and pings B. After "wg set peer remove" on
// A, the traffic stops in both directions.
func TestE2EWireGuardA12TwoSandboxesPublishedPort(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			a, bg := wgTwoSandboxes(t, b, `
ip link add wg0 type wireguard
wg set wg0 private-key /tmp/key listen-port 51820 peer "$WG_PUB_PEER" allowed-ips 10.77.0.2/32
ip addr add 10.77.0.1/24 dev wg0
ip link set wg0 up
echo A-READY
nc -l -p 9000 > /tmp/in < /dev/null
echo A-BYTES $(wc -c < /tmp/in)
echo A-SUM $(sha256sum /tmp/in | cut -d' ' -f1)
if ping -c 3 -W 3 10.77.0.2 >/dev/null; then echo A-PING-OK; else echo A-PING-FAILED; fi
wg set wg0 peer "$WG_PUB_PEER" remove
if ping -c 2 -W 2 10.77.0.2 >/dev/null 2>&1; then echo A-AFTER-REMOVE-REACHED; else echo A-AFTER-REMOVE-BLOCKED; fi
echo A-DONE
`, `
ip link add wg0 type wireguard
wg set wg0 private-key /tmp/key peer "$WG_PUB_PEER" endpoint "10.0.2.2:$WG_HOST_PORT" allowed-ips 10.77.0.1/32
ip addr add 10.77.0.2/24 dev wg0
ip link set wg0 up
if ping -c 3 -W 5 10.77.0.1 >/dev/null; then echo B-PING-OK; else echo B-PING-FAILED; fi
head -c 262144 /dev/urandom > /tmp/data
echo B-SUM $(sha256sum /tmp/data | cut -d' ' -f1)
nc -w 5 10.77.0.1 9000 < /tmp/data
echo B-SENT
read x || true
if ping -c 2 -W 2 10.77.0.1 >/dev/null 2>&1; then echo B-AFTER-REMOVE-REACHED; else echo B-AFTER-REMOVE-BLOCKED; fi
echo B-DONE
`)
			bg.wait(t, "B-PING-OK", 4*time.Minute)
			bSum := bg.wait(t, "B-SUM ", time.Minute)
			bg.wait(t, "B-SENT", time.Minute)
			aSum := a.wait(t, "A-SUM ", time.Minute)
			if aSum != bSum || len(aSum) != 64 {
				t.Errorf("A received sha256 %q, B sent %q", aSum, bSum)
			}
			a.wait(t, "A-PING-OK", time.Minute)
			a.wait(t, "A-AFTER-REMOVE-BLOCKED", time.Minute)
			a.wait(t, "A-DONE", time.Minute)
			bg.stdin.Close()
			bg.wait(t, "B-AFTER-REMOVE-BLOCKED", time.Minute)
			bg.wait(t, "B-DONE", time.Minute)
			if all := a.out.String() + bg.out.String(); strings.Contains(all, "REMOVE-REACHED") {
				t.Errorf("traffic crossed the tunnel after the peer was removed\nA:\n%s\nB:\n%s", a.out.String(), bg.out.String())
			}
		})
	}
}

// TestE2EWireGuardA12TwoSandboxesKeepalive links two sandboxes with a
// keepalive on B only. A publishes UDP port 51820 and has no endpoint for B.
// A learns the endpoint of B from the first keepalive, then pings B. After
// "wg set peer remove" on A, B cannot reach A.
func TestE2EWireGuardA12TwoSandboxesKeepalive(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			a, bg := wgTwoSandboxes(t, b, `
ip link add wg0 type wireguard
wg set wg0 private-key /tmp/key listen-port 51820 peer "$WG_PUB_PEER" allowed-ips 10.77.0.2/32
ip addr add 10.77.0.1/24 dev wg0
ip link set wg0 up
if [ -n "$(wg show wg0 endpoints | cut -f2 | grep :)" ]; then echo A-HAD-ENDPOINT; fi
echo A-READY
i=0
until [ -n "$(wg show wg0 endpoints | cut -f2 | grep :)" ]; do
	i=$((i+1))
	if [ $i -gt 120 ]; then echo A-NO-ENDPOINT; exit 1; fi
	sleep 1
done
echo A-LEARNED $(wg show wg0 endpoints | cut -f2)
if ping -c 3 -W 3 10.77.0.2 >/dev/null; then echo A-PING-OK; else echo A-PING-FAILED; fi
wg set wg0 peer "$WG_PUB_PEER" remove
if ping -c 2 -W 2 10.77.0.2 >/dev/null 2>&1; then echo A-AFTER-REMOVE-REACHED; else echo A-AFTER-REMOVE-BLOCKED; fi
echo A-DONE
`, `
ip link add wg0 type wireguard
ip addr add 10.77.0.2/24 dev wg0
ip link set wg0 up
wg set wg0 private-key /tmp/key peer "$WG_PUB_PEER" endpoint "10.0.2.2:$WG_HOST_PORT" allowed-ips 10.77.0.1/32 persistent-keepalive 1
echo B-KEEPALIVE-ON
read x || true
if ping -c 2 -W 2 10.77.0.1 >/dev/null 2>&1; then echo B-AFTER-REMOVE-REACHED; else echo B-AFTER-REMOVE-BLOCKED; fi
echo B-DONE
`)
			bg.wait(t, "B-KEEPALIVE-ON", 4*time.Minute)
			if got := a.wait(t, "A-LEARNED", 2*time.Minute); !strings.HasPrefix(got, "10.0.2.15:") {
				t.Errorf("A learned the endpoint %q, want one of the port forwarder, 10.0.2.15", got)
			}
			a.wait(t, "A-PING-OK", time.Minute)
			a.wait(t, "A-AFTER-REMOVE-BLOCKED", time.Minute)
			a.wait(t, "A-DONE", time.Minute)
			bg.stdin.Close()
			bg.wait(t, "B-AFTER-REMOVE-BLOCKED", time.Minute)
			bg.wait(t, "B-DONE", time.Minute)
			all := a.out.String() + bg.out.String()
			if strings.Contains(all, "A-HAD-ENDPOINT") || strings.Contains(all, "REMOVE-REACHED") {
				t.Errorf("A knew an endpoint of B before the keepalive, or traffic crossed after the removal\nA:\n%s\nB:\n%s", a.out.String(), bg.out.String())
			}
		})
	}
}

// TestE2EWireGuardA12ToolLargeConfiguration sets a configuration with many
// peers through "wg setconf" and reads it back with "wg show dump". The dump
// lists every peer, however many there are.
func TestE2EWireGuardA12ToolLargeConfiguration(t *testing.T) {
	const script = `set -e
apk add --no-cache wireguard-tools iproute2 >/dev/null
ip link add wg0 type wireguard
wg setconf wg0 /dev/stdin
echo SETCONF-DONE
rc=0
wg show wg0 dump > /tmp/dump 2> /tmp/err || rc=$?
echo DUMP-RC $rc
echo DUMP-LINES $(wc -l < /tmp/dump)
echo DUMP-ERR $(cat /tmp/err)
`
	for _, b := range gateBackends() {
		for _, peers := range []int{700, 2000, 10000} {
			t.Run(b.name+"/"+strconv.Itoa(peers), func(t *testing.T) {
				requireFixedAddressBackend(t, b)
				requireRegistry(t)
				var conf strings.Builder
				conf.WriteString("[Interface]\nPrivateKey = " + newWGKeys(t).private + "\nListenPort = 51820\n")
				for i := range peers {
					fmt.Fprintf(&conf, "[Peer]\nPublicKey = %s\nAllowedIPs = 172.%d.%d.%d/32\n", newWGKeys(t).public, 16+i>>16, i>>8&255, i&255)
				}
				out := mustRunGuest(t, guestSpec{
					plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script}, net: gvx.NetModeNAT, netRaw: true,
					stdin: strings.NewReader(conf.String()),
				})
				requireContains(t, "setconf", out, "SETCONF-DONE\n")
				rc := regexp.MustCompile(`(?m)^DUMP-RC (\d+)$`).FindStringSubmatch(out)
				lines := regexp.MustCompile(`(?m)^DUMP-LINES (\d+)$`).FindStringSubmatch(out)
				if rc == nil || lines == nil {
					t.Fatalf("output lacks the dump result:\n%s", out)
				}
				if rc[1] != "0" || lines[1] != strconv.Itoa(peers+1) {
					t.Errorf("the dump of %d peers ended with status %s and %s lines, want status 0 and %d lines:\n%s", peers, rc[1], lines[1], peers+1, out)
				}
			})
		}
	}
}
