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
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
)

// connmarkScript checks the CONNMARK target and the match connmark against the
// mark of a connection. The guest is the client. The namespace "peer" answers
// the datagrams of UDP port 9000 and the connections of TCP ports 9001 and
// 9002. The rules of the table mangle run for the packets of the client. A rule
// in PREROUTING drops each reply whose packet mark is not the saved mark, so a
// reply arrives only when the mark of the connection reached the reply packet.
// "conntrack -L" prints the mark of the connection.
const connmarkScript = `set -e
apk add --no-cache iptables iptables-legacy iproute2 python3 conntrack-tools >/dev/null
IPT=iptables-legacy
SAVE=iptables-legacy-save
RESTORE=iptables-legacy-restore
ok() { echo "$1"; }

ip netns add peer
ip link add v0 type veth peer name v1
ip link set v1 netns peer
ip addr add 10.1.0.1/24 dev v0
ip link set v0 up
ip -n peer addr add 10.1.0.2/24 dev v1
ip -n peer link set v1 up
ip -n peer link set lo up

cat >/tmp/serve.py <<'PY'
import socket, threading
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 9000))
    while True:
        data, addr = s.recvfrom(64)
        s.sendto(b"pong", addr)
def tcp(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(8)
    while True:
        c, _ = s.accept()
        c.sendall(b"pong")
        c.close()
for port in (9001, 9002):
    threading.Thread(target=tcp, args=(port,), daemon=True).start()
udp()
PY
cat >/tmp/dial.py <<'PY'
import socket, sys
proto, sport = sys.argv[1], int(sys.argv[2])
kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
s = socket.socket(socket.AF_INET, kind)
s.settimeout(3)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.1.0.1", int(sys.argv[3])))
try:
    if proto == "udp":
        s.sendto(b"ping", ("10.1.0.2", 9000))
    else:
        s.connect(("10.1.0.2", sport))
    print("got", s.recv(16).decode())
except (TimeoutError, OSError) as e:
    print("timeout" if isinstance(e, TimeoutError) else "error")
PY
ip netns exec peer python3 /tmp/serve.py &
sleep 2

# dial PROTO PEER-PORT LOCAL-PORT prints "got pong" or "timeout".
dial() { python3 /tmp/dial.py "$@"; }
# ctmark PROTO LOCAL-PORT prints the mark that conntrack shows for the flow.
ctmark() {
	conntrack -L -p "$1" 2>/dev/null | grep " sport=$2 " | sed -n 's/.* mark=\([0-9]*\).*/\1/p' | head -1
}
restore_rules() {
	$IPT -t mangle -A PREROUTING -p $1 --sport $2 -j CONNMARK --restore-mark
	$IPT -t mangle -A PREROUTING -p $1 --sport $2 -m mark ! --mark $3 -j DROP
}

# Save and restore. The packet mark 0x42 goes into the connection, and the
# reply gets it back. The reply of a flow without a saved mark is dropped.
$IPT -t mangle -A OUTPUT -p udp --sport 41001 -j MARK --set-mark 0x42
$IPT -t mangle -A OUTPUT -p udp --sport 41001 -j CONNMARK --save-mark
restore_rules udp 9000 0x42
echo UDP-SAVE-RESTORE $(dial udp 9000 41001) mark=$(ctmark udp 41001)
echo UDP-NO-SAVE $(dial udp 9000 41002) mark=$(ctmark udp 41002)

# The same on TCP: the SYN sets the mark and the SYN-ACK restores it.
$IPT -t mangle -A OUTPUT -p tcp --dport 9001 -j CONNMARK --set-mark 0x77
restore_rules tcp 9001:9002 0x77
echo TCP-SET-RESTORE $(dial tcp 9001 42001) mark=$(ctmark tcp 42001)
echo TCP-NO-SET $(dial tcp 9002 42002) mark=$(ctmark tcp 42002)
$IPT -t mangle -F

# Set with masks and the and, or, and xor spellings. Each result is the
# connection mark that conntrack prints.
$IPT -t mangle -A OUTPUT -p udp --sport 41003 -j CONNMARK --set-xmark 0x5/0xff
dial udp 9000 41003 >/dev/null
echo SET-XMARK mark=$(ctmark udp 41003)
$IPT -t mangle -A OUTPUT -p udp --sport 41004 -j CONNMARK --set-mark 0xf0
$IPT -t mangle -A OUTPUT -p udp --sport 41004 -j CONNMARK --or-mark 0x0f
$IPT -t mangle -A OUTPUT -p udp --sport 41004 -j CONNMARK --and-mark 0x3c
$IPT -t mangle -A OUTPUT -p udp --sport 41004 -j CONNMARK --xor-mark 0x01
dial udp 9000 41004 >/dev/null
echo AND-OR-XOR mark=$(ctmark udp 41004)
$IPT -t mangle -F

# Save and restore through masks. The save keeps the high byte of 0xabcd. The
# restore puts the high byte of the connection into the reply packet.
$IPT -t mangle -A OUTPUT -p udp --sport 41005 -j MARK --set-mark 0xabcd
$IPT -t mangle -A OUTPUT -p udp --sport 41005 -j CONNMARK --save-mark --nfmask 0xff00 --ctmask 0xffff
$IPT -t mangle -A PREROUTING -p udp --dport 41005 -j CONNMARK --restore-mark --nfmask 0xff --ctmask 0xff00
$IPT -t mangle -A PREROUTING -p udp --dport 41005 -m mark ! --mark 0xab00 -j DROP
echo MASKED-SAVE-RESTORE $(dial udp 9000 41005) mark=$(ctmark udp 41005)
$IPT -t mangle -F

# The match connmark selects the packets of the connection that holds the mark.
$IPT -t mangle -A OUTPUT -p udp --sport 41006 -j CONNMARK --set-mark 0x42
dial udp 9000 41006 >/dev/null
echo CONNMARK-NOT-YET mark=$(ctmark udp 41006)
for m in "--mark 0x42" "--mark 0x40/0xf0" "! --mark 0x41"; do
	$IPT -t mangle -A PREROUTING -p udp --dport 41006 -m connmark $m -j DROP
	echo "CONNMARK-DROP [$m] $(dial udp 9000 41006)"
	$IPT -t mangle -F PREROUTING
done
for m in "! --mark 0x42" "--mark 0x43" "--mark 0x1/0xf"; do
	$IPT -t mangle -A PREROUTING -p udp --dport 41006 -m connmark $m -j DROP
	echo "CONNMARK-PASS [$m] $(dial udp 9000 41006)"
	$IPT -t mangle -F PREROUTING
done
$IPT -t mangle -F

# conntrack selects the flows by their mark.
echo CT-FILTER $(conntrack -L -p udp -m 66 2>&1 | grep -c ' sport=4100[0-9] ' || true) $(conntrack -L -p udp -m 66 2>&1 | grep -c ' sport=41006 ' || true)

# iptables-save prints each rule, and iptables-restore reads the output.
$IPT -t mangle -A PREROUTING -p udp -j CONNMARK --restore-mark
$IPT -t mangle -A PREROUTING -p tcp -j CONNMARK --restore-mark --nfmask 0xff --ctmask 0xff00
$IPT -t mangle -A POSTROUTING -p udp -m mark --mark 0xca6c -j CONNMARK --save-mark
$IPT -t mangle -A POSTROUTING -p tcp -j CONNMARK --save-mark --nfmask 0xf0 --ctmask 0xf
$IPT -t mangle -A OUTPUT -j CONNMARK --set-xmark 0x1/0xff
$IPT -t mangle -A OUTPUT -j CONNMARK --set-mark 0x20
$IPT -t mangle -A OUTPUT -j CONNMARK --and-mark 0xf0
$IPT -t mangle -A OUTPUT -j CONNMARK --or-mark 0x3
$IPT -t mangle -A OUTPUT -j CONNMARK --xor-mark 0x7
$IPT -t mangle -A OUTPUT -j CONNMARK --set-xmark 0x1/0xff --left-shift-mark 4
$IPT -t mangle -A OUTPUT -j CONNMARK --save-mark --nfmask 0xff --right-shift-mark 8
$IPT -t mangle -A OUTPUT -m connmark --mark 0x11 -j RETURN
$IPT -t mangle -A OUTPUT -m connmark ! --mark 0x12/0xff -j RETURN
$IPT -t nat -A OUTPUT -p tcp --dport 1 -j CONNMARK --set-mark 0x5
$IPT -t filter -A OUTPUT -p tcp --dport 2 -j CONNMARK --set-mark 0x6
$IPT -t raw -A PREROUTING -p tcp --dport 3 -j CONNMARK --set-mark 0x7
$SAVE | grep -i connmark > /tmp/save1
cat /tmp/save1 | sed 's/^/SAVE1 /'
$SAVE > /tmp/all1
$IPT -t mangle -F
$IPT -t nat -F
$IPT -t filter -F
$IPT -t raw -F
$RESTORE < /tmp/all1
$SAVE | grep -i connmark > /tmp/save2
if cmp -s /tmp/save1 /tmp/save2; then ok SAVE-ROUNDTRIP-SAME; else echo FAIL roundtrip; diff /tmp/save1 /tmp/save2; fi
echo SAVE-COUNT $(cat /tmp/save2 | wc -l)
ok CONNMARK-DONE
`

// connmarkField returns the text after "name " on the first line with that
// prefix.
func connmarkField(t *testing.T, out, name string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(l, name+" "); ok {
			return rest
		}
	}
	t.Fatalf("output lacks %s; full output:\n%s", name, out)
	return ""
}

// TestE2ENetfilterConnmark runs rules with the target CONNMARK and the match
// connmark. A mark that one packet saves reaches the other packets of the same
// connection, conntrack prints the mark, and iptables-save reads the rules.
func TestE2ENetfilterConnmark(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", connmarkScript}, net: gvx.NetModeNAT, netRaw: true,
			})
			t.Log(out)
			want := func(name, value string) {
				t.Helper()
				if got := connmarkField(t, out, name); got != value {
					t.Errorf("%s = %q, want %q", name, got, value)
				}
			}
			want("UDP-SAVE-RESTORE", "got pong mark=66")
			want("UDP-NO-SAVE", "timeout mark=0")
			want("TCP-SET-RESTORE", "got pong mark=119")
			want("TCP-NO-SET", "timeout mark=0")
			want("SET-XMARK", "mark=5")
			want("AND-OR-XOR", "mark=61")
			want("MASKED-SAVE-RESTORE", "got pong mark=43776")
			want("CONNMARK-NOT-YET", "mark=66")
			requireContains(t, "connmark drops", out,
				"CONNMARK-DROP [--mark 0x42] timeout\n", "CONNMARK-DROP [--mark 0x40/0xf0] timeout\n", "CONNMARK-DROP [! --mark 0x41] timeout\n",
				"CONNMARK-PASS [! --mark 0x42] got pong\n", "CONNMARK-PASS [--mark 0x43] got pong\n", "CONNMARK-PASS [--mark 0x1/0xf] got pong\n")
			want("CT-FILTER", "2 1")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
			requireContains(t, "iptables-save", out,
				"SAVE1 -A PREROUTING -p udp -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n",
				"SAVE1 -A PREROUTING -p tcp -j CONNMARK --restore-mark --nfmask 0xff --ctmask 0xff00\n",
				"SAVE1 -A POSTROUTING -p udp -m mark --mark 0xca6c -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff\n",
				"SAVE1 -A POSTROUTING -p tcp -j CONNMARK --save-mark --nfmask 0xf0 --ctmask 0xf\n",
				"SAVE1 -A OUTPUT -j CONNMARK --set-xmark 0x1/0xff\n",
				"SAVE1 -A OUTPUT -j CONNMARK --set-xmark 0x0/0xffffff0f\n",
				"SAVE1 -A OUTPUT -j CONNMARK --set-xmark 0x3/0x3\n",
				"SAVE1 -A OUTPUT -j CONNMARK --set-xmark 0x7/0x0\n",
				"SAVE1 -A OUTPUT -j CONNMARK --set-xmark 0x1/0xff --left-shift-mark 4\n",
				"SAVE1 -A OUTPUT -j CONNMARK --save-mark --nfmask 0xff --ctmask 0xffffffff --right-shift-mark 8\n",
				"SAVE1 -A OUTPUT -m connmark --mark 0x11 -j RETURN\n",
				"SAVE1 -A OUTPUT -m connmark ! --mark 0x12/0xff -j RETURN\n",
				"SAVE1 -A OUTPUT -p tcp -m tcp --dport 2 -j CONNMARK --set-xmark 0x6/0xffffffff\n",
				"SAVE1 -A OUTPUT -p tcp -m tcp --dport 1 -j CONNMARK --set-xmark 0x5/0xffffffff\n",
				"SAVE1 -A PREROUTING -p tcp -m tcp --dport 3 -j CONNMARK --set-xmark 0x7/0xffffffff\n",
				"SAVE-ROUNDTRIP-SAME\n", "SAVE-COUNT 16\n", "CONNMARK-DONE\n")
		})
	}
}
