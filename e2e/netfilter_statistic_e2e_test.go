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
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

// The tests in this file drive the legacy iptables binary in an Alpine guest
// with the rules that kube-proxy writes for a service with two endpoints. A
// nat OUTPUT rule with the statistic match picks one of two DNAT targets on
// loopback, and the probe statprobe counts which listener each new connection
// reaches. The unit tests in pkg/sentry/socket/netfilter carry the offline
// coverage of the match.

const (
	// statServiceAddr is the virtual service address. No interface holds it;
	// the DNAT rules move each connection to a listener.
	statServiceAddr = "127.0.0.2:80"
	statTargetA     = "127.0.0.1:8081"
	statTargetB     = "127.0.0.1:8082"
)

// statisticScriptHead installs the tools, copies the probe, and defines the
// helpers that the phase scripts use. The first nat OUTPUT rule holds the
// statistic match and sends matching connections to listener A. The second
// rule sends every other connection to listener B. Each phase passes its own
// range of source ports to the probe. The connection tracking of the guest
// keeps the NAT target of a closed connection for up to two minutes, and a new
// connection with the same addresses and ports reuses that target instead of
// asking the rules again.
const statisticScriptHead = `set -e
apk add --no-cache iptables iptables-legacy >/dev/null
cp /workspace/statprobe /usr/local/bin/statprobe
chmod 755 /usr/local/bin/statprobe
ipt=iptables-legacy
svc='-d 127.0.0.2 -p tcp --dport 80'
toA='-j DNAT --to-destination 127.0.0.1:8081'
toB='-j DNAT --to-destination 127.0.0.1:8082'
rule_b() { $ipt -t nat -A OUTPUT $svc $toB; }
probe() { echo "PHASE $1"; statprobe split ` + statServiceAddr + ` ` + statTargetA + ` ` + statTargetB + ` $2 tcp $3; }
`

// statResultPattern matches the output of one phase of the probe.
var statResultPattern = regexp.MustCompile(`PHASE (\S+)\nRESULT a=(\d+) b=(\d+)(?: order=([AB?]*))?\n`)

// statPhase is the parsed answer of statprobe for one phase.
type statPhase struct {
	a, b  int
	order string
}

// parseStatPhases returns the phases that the guest printed, keyed by name.
func parseStatPhases(t *testing.T, out string) map[string]statPhase {
	t.Helper()
	phases := map[string]statPhase{}
	for _, m := range statResultPattern.FindAllStringSubmatch(out, -1) {
		a, errA := strconv.Atoi(m[2])
		b, errB := strconv.Atoi(m[3])
		if errA != nil || errB != nil {
			t.Fatalf("phase %s: unreadable counts %q %q", m[1], m[2], m[3])
		}
		phases[m[1]] = statPhase{a: a, b: b, order: m[4]}
	}
	return phases
}

// requireStatPhase returns the named phase or fails the test with the output.
func requireStatPhase(t *testing.T, phases map[string]statPhase, out, name string) statPhase {
	t.Helper()
	p, ok := phases[name]
	if !ok {
		t.Fatalf("guest output has no result for phase %q; full output:\n%s", name, out)
	}
	return p
}

// runStatisticGuest copies statprobe into a workspace and runs script in an
// Alpine guest with raw sockets. The probe makes real connections, so the
// guest keeps the NAT network for the package install.
func runStatisticGuest(t *testing.T, b gateBackend, script string) string {
	t.Helper()
	dir := t.TempDir()
	data, err := os.ReadFile(acceptprog.BuildStatProbe(t, hostArch()))
	if err != nil {
		t.Fatalf("read statprobe: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "statprobe"), data, 0o755); err != nil {
		t.Fatalf("copy statprobe into the workspace: %v", err)
	}
	return mustRunGuest(t, guestSpec{
		plat:      b.plat,
		image:     "alpine:3.20",
		argv:      []string{"sh", "-c", script},
		workspace: dir,
		net:       gvx.NetModeNAT,
		netRaw:    true,
		timeout:   5 * time.Minute,
	})
}

// repeat returns unit repeated n times.
func repeat(unit string, n int) string { return strings.Repeat(unit, n) }

// TestE2ENetfilterStatisticA8Random checks that the random mode splits 2000
// connections within 5% of an even share, that probability 1 sends every
// connection to the first target, and that probability 0 sends none.
func TestE2ENetfilterStatisticA8Random(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			script := statisticScriptHead + `
$ipt -t nat -A OUTPUT $svc -m statistic --mode random --probability 0.5 $toA
rule_b
$ipt -t nat -S OUTPUT
$ipt -t nat -C OUTPUT $svc -m statistic --mode random --probability 0.5 $toA && echo CHECK-RANDOM-OK
probe half 2000 20000
$ipt -t nat -R OUTPUT 1 $svc -m statistic --mode random --probability 1 $toA
$ipt -t nat -S OUTPUT
probe all 200 30000
$ipt -t nat -R OUTPUT 1 $svc -m statistic --mode random --probability 0 $toA
$ipt -t nat -S OUTPUT
probe none 200 31000
`
			out := runStatisticGuest(t, b, script)
			t.Logf("guest output:\n%s", out)
			requireContains(t, "guest output", out,
				"-m statistic --mode random --probability 0.50000000000",
				"-m statistic --mode random --probability 1.00000000000",
				"-m statistic --mode random --probability 0.00000000000",
				"CHECK-RANDOM-OK\n")
			phases := parseStatPhases(t, out)

			half := requireStatPhase(t, phases, out, "half")
			if half.a+half.b != 2000 || half.a < 900 || half.a > 1100 || half.b < 900 || half.b > 1100 {
				t.Errorf("probability 0.5 split 2000 connections into a=%d b=%d, want each in 900..1100", half.a, half.b)
			}
			if all := requireStatPhase(t, phases, out, "all"); all.a != 200 || all.b != 0 {
				t.Errorf("probability 1 split 200 connections into a=%d b=%d, want a=200 b=0", all.a, all.b)
			}
			if none := requireStatPhase(t, phases, out, "none"); none.a != 0 || none.b != 200 {
				t.Errorf("probability 0 split 200 connections into a=%d b=%d, want a=0 b=200", none.a, none.b)
			}
		})
	}
}

// TestE2ENetfilterStatisticA9Nth checks that the nth mode matches the
// connections at the positions that --every and --packet name, that the
// inversion matches the other connections, and that iptables reads the rule
// back in the form that "iptables -C" needs.
func TestE2ENetfilterStatisticA9Nth(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			script := statisticScriptHead + `
$ipt -t nat -A OUTPUT $svc -m statistic --mode nth --every 3 --packet 0 $toA
rule_b
$ipt -t nat -S OUTPUT
$ipt -t nat -C OUTPUT $svc -m statistic --mode nth --every 3 --packet 0 $toA && echo CHECK-NTH-OK
probe packet0 30 20000
$ipt -t nat -R OUTPUT 1 $svc -m statistic --mode nth --every 3 --packet 1 $toA
probe packet1 30 21000
$ipt -t nat -R OUTPUT 1 $svc -m statistic --mode nth --every 3 --packet 2 $toA
probe packet2 30 22000
$ipt -t nat -R OUTPUT 1 $svc -m statistic --mode nth ! --every 3 --packet 0 $toA
$ipt -t nat -S OUTPUT
$ipt -t nat -C OUTPUT $svc -m statistic --mode nth ! --every 3 --packet 0 $toA && echo CHECK-INVERTED-OK
probe inverted 30 23000
`
			out := runStatisticGuest(t, b, script)
			t.Logf("guest output:\n%s", out)
			requireContains(t, "guest output", out,
				"-m statistic --mode nth --every 3 --packet 0 ",
				"-m statistic --mode nth ! --every 3 --packet 0 ",
				"CHECK-NTH-OK\n", "CHECK-INVERTED-OK\n")
			phases := parseStatPhases(t, out)

			// Listener A holds the connections that the statistic rule matches.
			// The first connection is position 1.
			want := []struct {
				phase string
				a, b  int
				order string
			}{
				{"packet0", 10, 20, repeat("ABB", 10)},
				{"packet1", 10, 20, repeat("BAB", 10)},
				{"packet2", 10, 20, repeat("BBA", 10)},
				{"inverted", 20, 10, repeat("BAA", 10)},
			}
			for _, w := range want {
				got := requireStatPhase(t, phases, out, w.phase)
				if got.a != w.a || got.b != w.b || got.order != w.order {
					t.Errorf("phase %s: a=%d b=%d order=%q, want %s", w.phase, got.a, got.b, got.order,
						fmt.Sprintf("a=%d b=%d order=%q", w.a, w.b, w.order))
				}
			}
		})
	}
}
