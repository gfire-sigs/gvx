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
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// wgPortBusy is a shell function that prints "busy" when a UDP socket cannot
// bind port $1 and "free" when it can. A free port makes nc wait until the
// timeout ends it, and a busy port makes nc fail at once.
const wgPortBusy = `port_state() {
	timeout 2 nc -u -l -p "$1" </dev/null >/dev/null 2>&1
	if [ $? -ge 124 ]; then echo free; else echo busy; fi
}
`

// TestE2EWireGuardA12TwoSandboxesLinkState links two sandboxes and takes the
// link of A down and up. A new link is down and owns no port. While the link
// of A is down, the port is free and no traffic crosses the tunnel in either
// direction. After the up, the port is bound again and the traffic returns.
func TestE2EWireGuardA12TwoSandboxesLinkState(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			a, bg := wgTwoSandboxes(t, b, wgPortBusy+`
ip link add wg0 type wireguard
echo A-FLAGS-NEW $(ip -o link show wg0 | tr '\n' ' ')
wg set wg0 private-key /tmp/key listen-port 51820 peer "$WG_PUB_PEER" allowed-ips 10.77.0.2/32
ip addr add 10.77.0.1/24 dev wg0
echo A-PORT-BEFORE-UP $(port_state 51820)
ip link set wg0 up
echo A-FLAGS-UP $(ip -o link show wg0 | tr '\n' ' ')
echo A-READY
read x
ip link set wg0 down
echo A-FLAGS-DOWN $(ip -o link show wg0 | tr '\n' ' ')
echo A-PORT-AFTER-DOWN $(port_state 51820)
echo A-LISTEN-AFTER-DOWN $(wg show wg0 listen-port)
if ping -c 2 -W 2 10.77.0.2 >/dev/null 2>&1; then echo A-DOWN-REACHED; else echo A-DOWN-BLOCKED; fi
echo A-DOWNED
read x
ip link set wg0 up
echo A-PORT-AFTER-UP $(port_state 51820)
i=0
until ping -c 1 -W 2 10.77.0.2 >/dev/null 2>&1; do
	i=$((i+1))
	if [ $i -gt 40 ]; then echo A-UP-NO-TRAFFIC; exit 1; fi
done
echo A-UP-RESTORED
echo A-DONE
`, `
ip link add wg0 type wireguard
wg set wg0 private-key /tmp/key peer "$WG_PUB_PEER" endpoint "10.0.2.2:$WG_HOST_PORT" allowed-ips 10.77.0.1/32
ip addr add 10.77.0.2/24 dev wg0
ip link set wg0 up
if ping -c 3 -W 5 10.77.0.1 >/dev/null; then echo B-PING-OK; else echo B-PING-FAILED; fi
read x
if ping -c 2 -W 2 10.77.0.1 >/dev/null 2>&1; then echo B-DOWN-REACHED; else echo B-DOWN-BLOCKED; fi
read x
i=0
until ping -c 1 -W 2 10.77.0.1 >/dev/null 2>&1; do
	i=$((i+1))
	if [ $i -gt 60 ]; then echo B-UP-NO-TRAFFIC; exit 1; fi
done
echo B-UP-RESTORED
echo B-DONE
`)
			bg.wait(t, "B-PING-OK", 4*time.Minute)
			step := func(g *runningGuest) {
				t.Helper()
				if _, err := g.stdin.Write([]byte("go\n")); err != nil {
					t.Fatalf("write to the guest: %v", err)
				}
			}
			step(a)
			a.wait(t, "A-DOWNED", 2*time.Minute)
			step(bg)
			bg.wait(t, "B-DOWN-BLOCKED", 2*time.Minute)
			step(a)
			a.wait(t, "A-UP-RESTORED", 4*time.Minute)
			step(bg)
			bg.wait(t, "B-UP-RESTORED", 4*time.Minute)
			a.wait(t, "A-DONE", time.Minute)
			bg.wait(t, "B-DONE", time.Minute)

			all := a.out.String() + bg.out.String()
			for _, want := range []string{"A-PORT-BEFORE-UP free", "A-PORT-AFTER-DOWN free", "A-LISTEN-AFTER-DOWN 51820", "A-PORT-AFTER-UP busy", "A-DOWN-BLOCKED", "B-DOWN-BLOCKED"} {
				if !strings.Contains(all, want) {
					t.Errorf("output lacks %q\nA:\n%s\nB:\n%s", want, a.out.String(), bg.out.String())
				}
			}
			for _, bad := range []string{"A-DOWN-REACHED", "B-DOWN-REACHED", "NO-TRAFFIC"} {
				if strings.Contains(all, bad) {
					t.Errorf("output has %q\nA:\n%s\nB:\n%s", bad, a.out.String(), bg.out.String())
				}
			}
			// The flags of Linux: a new link is down, and an up link has
			// POINTOPOINT, NOARP, UP, and LOWER_UP with the state UNKNOWN.
			field := func(name string) string {
				m := regexp.MustCompile(`(?m)^` + name + ` (.*)$`).FindStringSubmatch(a.out.String())
				if m == nil {
					t.Fatalf("output of A lacks %s:\n%s", name, a.out.String())
				}
				return m[1]
			}
			if s := field("A-FLAGS-NEW"); strings.Contains(s, "UP") || !strings.Contains(s, "POINTOPOINT,NOARP") || !strings.Contains(s, "state DOWN") {
				t.Errorf("a new link shows %q, want POINTOPOINT,NOARP and state DOWN without UP", s)
			}
			if s := field("A-FLAGS-UP"); !strings.Contains(s, "<POINTOPOINT,NOARP,UP,LOWER_UP>") || !strings.Contains(s, "state UNKNOWN") {
				t.Errorf("an up link shows %q, want <POINTOPOINT,NOARP,UP,LOWER_UP> and state UNKNOWN", s)
			}
			if s := field("A-FLAGS-DOWN"); strings.Contains(s, ",UP") || !strings.Contains(s, "state DOWN") {
				t.Errorf("a link after down shows %q, want no UP and state DOWN", s)
			}
		})
	}
}

// TestE2EWireGuardA12ToolManyPeers sets 10,000 peers on one link with a single
// "wg set" and reads them back with "wg show dump", "wg show peers", and "wg
// showconf". Linux has no limit below 1,048,576 peers, and a dump of any size
// reaches the reader.
func TestE2EWireGuardA12ToolManyPeers(t *testing.T) {
	const peers = 10000
	const script = `set -e
apk add --no-cache wireguard-tools iproute2 >/dev/null
ip link add wg0 type wireguard
wg genkey > /tmp/priv
wg set wg0 private-key /tmp/priv listen-port 51820 $(cat)
echo SET-DONE
wg show wg0 dump > /tmp/dump
echo DUMP-LINES $(wc -l < /tmp/dump)
echo DUMP-FIRST $(sed -n 2p /tmp/dump | cut -f1,4)
echo DUMP-LAST $(sed -n '$p' /tmp/dump | cut -f1,4)
echo PEER-LINES $(wg show wg0 peers | wc -l)
echo SHOWCONF-PEERS $(wg showconf wg0 | grep -c '^\[Peer\]')
echo SHOW-PEERS $(wg show wg0 | grep -c '^peer:')
`
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			var args strings.Builder
			var first, last wgKeys
			for i := range peers {
				k := newWGKeys(t)
				if i == 0 {
					first = k
				}
				last = k
				fmt.Fprintf(&args, "peer %s allowed-ips 172.%d.%d.%d/32\n", k.public, 16+i>>16, i>>8&255, i&255)
			}
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script}, net: gvx.NetModeNAT, netRaw: true,
				stdin: strings.NewReader(args.String()), timeout: 8 * time.Minute,
			})
			requireContains(t, "wg output", out, "SET-DONE\n",
				"DUMP-LINES "+strconv.Itoa(peers+1)+"\n",
				"DUMP-FIRST "+first.public+" 172.16.0.0/32\n",
				"DUMP-LAST "+last.public+" 172.16."+strconv.Itoa((peers-1)>>8&255)+"."+strconv.Itoa((peers-1)&255)+"/32\n",
				"PEER-LINES "+strconv.Itoa(peers)+"\n", "SHOWCONF-PEERS "+strconv.Itoa(peers)+"\n", "SHOW-PEERS "+strconv.Itoa(peers)+"\n")
		})
	}
}

// TestE2EWireGuardA12TwoSandboxesFwmark checks that the fwmark of the link
// marks the encrypted packets, as the mark of a Linux wireguard link does. B
// has an iptables rule in the OUTPUT chain that drops the UDP packets for the
// port of A with the mark 0x51. With "fwmark 0x51" the tunnel stops. With
// "fwmark 0x52", or with the mark off, the rule does not match and the traffic
// returns. The iptables counters of the stack stay at 0 for every rule, so the
// test observes the drop and not a counter.
func TestE2EWireGuardA12TwoSandboxesFwmark(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			_, bg := wgTwoSandboxes(t, b, `
ip link add wg0 type wireguard
wg set wg0 private-key /tmp/key listen-port 51820 peer "$WG_PUB_PEER" allowed-ips 10.77.0.2/32
ip addr add 10.77.0.1/24 dev wg0
ip link set wg0 up
echo A-READY
read x
`, `
apk add --no-cache iptables iptables-legacy >/dev/null
ipt="iptables-legacy -w"
reach() { ping -c "$1" -W 2 10.77.0.1 >/dev/null 2>&1; }
ip link add wg0 type wireguard
wg set wg0 private-key /tmp/key fwmark 0x51 peer "$WG_PUB_PEER" endpoint "10.0.2.2:$WG_HOST_PORT" allowed-ips 10.77.0.1/32
ip addr add 10.77.0.2/24 dev wg0
ip link set wg0 up
echo B-FWMARK $(wg show wg0 fwmark)
if ping -c 3 -W 5 10.77.0.1 >/dev/null; then echo B-PING-OK; else echo B-PING-FAILED; fi
$ipt -A OUTPUT -p udp --dport "$WG_HOST_PORT" -m mark --mark 0x51 -j DROP
if reach 2; then echo B-MARK-51-REACHED; else echo B-MARK-51-DROPPED; fi
wg set wg0 fwmark 0x52
echo B-FWMARK $(wg show wg0 fwmark)
i=0
until reach 1; do
	i=$((i+1))
	if [ $i -gt 30 ]; then echo B-MARK-52-DROPPED; break; fi
done
if [ $i -le 30 ]; then echo B-MARK-52-REACHED; fi
wg set wg0 fwmark 0x51
if reach 2; then echo B-AGAIN-51-REACHED; else echo B-AGAIN-51-DROPPED; fi
wg set wg0 fwmark off
echo B-FWMARK $(wg show wg0 fwmark)
i=0
until reach 1; do
	i=$((i+1))
	if [ $i -gt 30 ]; then echo B-OFF-DROPPED; break; fi
done
if [ $i -le 30 ]; then echo B-OFF-REACHED; fi
echo B-DONE
`)
			bg.wait(t, "B-DONE", 5*time.Minute)
			out := bg.out.String()
			for _, want := range []string{"B-FWMARK 0x51\n", "B-PING-OK\n", "B-MARK-51-DROPPED\n", "B-FWMARK 0x52\n", "B-MARK-52-REACHED\n", "B-AGAIN-51-DROPPED\n", "B-FWMARK off\n", "B-OFF-REACHED\n"} {
				if !strings.Contains(out, want) {
					t.Errorf("output of B lacks %q\nB:\n%s", want, out)
				}
			}
			for _, bad := range []string{"B-PING-FAILED", "B-MARK-51-REACHED", "B-MARK-52-DROPPED", "B-AGAIN-51-REACHED", "B-OFF-DROPPED"} {
				if strings.Contains(out, bad) {
					t.Errorf("output of B has %q\nB:\n%s", bad, out)
				}
			}
		})
	}
}

// TestE2EWireGuardA12ToolPeerSemantics checks the peer rules of the kernel with
// the tools: an allowed IP address moves between peers, a keepalive of 0 and a
// zero preshared key switch their features off, and "remove" of a peer that
// does not exist succeeds and changes nothing.
func TestE2EWireGuardA12ToolPeerSemantics(t *testing.T) {
	const script = `set -e
apk add --no-cache wireguard-tools iproute2 >/dev/null
umask 077
wg genkey > /tmp/priv
wg genpsk > /tmp/psk
head -c 32 /dev/zero | base64 > /tmp/zero
ip link add wg0 type wireguard
wg set wg0 private-key /tmp/priv
wg set wg0 peer "$PEER_A" allowed-ips 10.60.0.0/24,10.61.0.0/16 persistent-keepalive 25 preshared-key /tmp/psk
wg set wg0 peer "$PEER_B" allowed-ips 10.60.0.0/25
echo STEP1-A $(wg show wg0 allowed-ips | grep "$PEER_A" | cut -f2)
echo STEP1-B $(wg show wg0 allowed-ips | grep "$PEER_B" | cut -f2)
wg set wg0 peer "$PEER_B" allowed-ips 10.60.0.0/24
echo STEP2-A $(wg show wg0 allowed-ips | grep "$PEER_A" | cut -f2)
echo STEP2-B $(wg show wg0 allowed-ips | grep "$PEER_B" | cut -f2)
wg set wg0 peer "$PEER_A" persistent-keepalive 0 preshared-key /tmp/zero
echo KEEPALIVE-A $(wg show wg0 persistent-keepalive | grep "$PEER_A" | cut -f2)
echo PSK-A $(wg show wg0 preshared-keys | grep "$PEER_A" | cut -f2)
wg set wg0 peer "$PEER_X" endpoint 192.0.2.1:1 allowed-ips 10.70.0.0/16 remove
echo PEERS $(wg show wg0 peers | wc -l)
wg set wg0 peer "$PEER_A" allowed-ips 10.99.0.0/16
wg set wg0 peer "$PEER_A" remove
echo STEP3-B $(wg show wg0 allowed-ips | grep "$PEER_B" | cut -f2)
echo PEERS-AFTER-REMOVE $(wg show wg0 peers | wc -l)
`
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			a, bb, x := newWGKeys(t), newWGKeys(t), newWGKeys(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script}, net: gvx.NetModeNAT, netRaw: true,
				envv: []string{"PEER_A=" + a.public, "PEER_B=" + bb.public, "PEER_X=" + x.public},
			})
			requireContains(t, "wg output", out,
				"STEP1-A 10.60.0.0/24 10.61.0.0/16\n", "STEP1-B 10.60.0.0/25\n",
				"STEP2-A 10.61.0.0/16\n", "STEP2-B 10.60.0.0/24\n",
				"KEEPALIVE-A off\n", "PSK-A (none)\n", "PEERS 2\n",
				"STEP3-B 10.60.0.0/24\n", "PEERS-AFTER-REMOVE 1\n")
		})
	}
}

// TestE2EWireGuardA12ToolLinkRequests checks the order of a link request and
// the state files of the link. A request with an invalid MTU and "up" fails and
// leaves the link down, because Linux applies the flags last. A route through a
// link that is down fails with ENETDOWN, and works after the up. The files in
// /sys/class/net report the state "unknown" while the link is up, and an empty
// address.
func TestE2EWireGuardA12ToolLinkRequests(t *testing.T) {
	const script = `
apk add --no-cache iproute2 >/dev/null
ip link add wg0 type wireguard
echo OPER-DOWN $(cat /sys/class/net/wg0/operstate)
echo ADDRESS-LEN $(wc -c < /sys/class/net/wg0/address)
if ip link set wg0 mtu 10 up 2>/dev/null; then echo BADMTU-OK; else echo BADMTU-FAILED; fi
echo FLAGS-AFTER-BADMTU $(ip -o link show wg0 | grep -c '[<,]UP[,>]')
echo MTU-AFTER-BADMTU $(cat /sys/class/net/wg0/mtu)
echo ROUTE-DOWN $(ip route add 10.5.0.0/24 dev wg0 2>&1)
ip link set wg0 mtu 1400 up
echo OPER-UP $(cat /sys/class/net/wg0/operstate)
ip route add 10.5.0.0/24 dev wg0 && echo ROUTE-UP-OK
echo MTU-AFTER-GOOD $(cat /sys/class/net/wg0/mtu)
`
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script}, net: gvx.NetModeNAT, netRaw: true,
			})
			requireContains(t, "output", out, "OPER-DOWN down\n", "ADDRESS-LEN 1\n", "BADMTU-FAILED\n",
				"FLAGS-AFTER-BADMTU 0\n", "MTU-AFTER-BADMTU 1420\n", "Network is down", "OPER-UP unknown\n",
				"ROUTE-UP-OK\n", "MTU-AFTER-GOOD 1400\n")
		})
	}
}
