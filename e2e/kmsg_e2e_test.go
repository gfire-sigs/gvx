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
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
)

// TestE2EKernelLogDmesg writes a line to /dev/kmsg in an alpine guest and
// reads it with the busybox dmesg, which calls syslog(2). It checks the boot
// messages, the text form with and without the raw prefix, and that dmesg -c
// clears the log.
func TestE2EKernelLogDmesg(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			script := `set -e
echo '<6>gvx-e2e-dmesg-line' > /dev/kmsg
dmesg | grep -q 'gvx-e2e-dmesg-line' && echo DMESG-HAS-LINE
dmesg | grep -q 'Starting gVisor' && echo DMESG-HAS-BOOT
dmesg -r | grep -q '^<14>\[ *[0-9]*\.[0-9]*\] gvx-e2e-dmesg-line$' && echo DMESG-RAW-FORM
dmesg -c > /dev/null
test -z "$(dmesg)" && echo DMESG-CLEARED
echo '<6>gvx-e2e-after-clear' > /dev/kmsg
test "$(dmesg | wc -l)" = 1 && dmesg | grep -q 'gvx-e2e-after-clear' && echo DMESG-ONLY-NEW
`
			out := mustRunGuest(t, guestSpec{
				plat:  b.plat,
				image: "alpine:3.20",
				argv:  []string{"sh", "-c", script},
			})
			requireContains(t, "guest output", out,
				"DMESG-HAS-LINE\n", "DMESG-HAS-BOOT\n", "DMESG-RAW-FORM\n", "DMESG-CLEARED\n", "DMESG-ONLY-NEW\n")
		})
	}
}

// TestE2EKernelLogIptablesLog adds iptables LOG rules to the INPUT and OUTPUT
// chains, sends a UDP datagram to the loopback address, and reads the lines
// with dmesg. The line has the prefix, the interface names, the fields of the
// IP and UDP headers, and the level of the rule.
func TestE2EKernelLogIptablesLog(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			script := `set -e
apk add --no-cache iptables iptables-legacy >/dev/null
ipt="iptables-legacy -w"
$ipt -A INPUT -i lo -p udp --dport 9999 -j LOG --log-prefix 'GVXIN: ' --log-level 5
$ipt -A OUTPUT -o lo -p udp --dport 9999 -j LOG --log-prefix 'GVXOUT: '
$ipt -S INPUT | grep -q -- '--log-prefix "GVXIN: " --log-level 5' && echo SAVE-OK
dmesg -c > /dev/null
echo hello | nc -u -w1 127.0.0.1 9999 || true
dmesg -r > /tmp/log.txt
grep -E '^<5>\[ *[0-9.]*\] GVXIN: IN=lo OUT= MAC=[0-9a-f:]* SRC=127.0.0.1 DST=127.0.0.1 LEN=34 .*PROTO=UDP SPT=[0-9]+ DPT=9999 LEN=14 ' /tmp/log.txt >/dev/null && echo LOG-IN
grep -E '^<4>\[ *[0-9.]*\] GVXOUT: IN= OUT=lo SRC=127.0.0.1 DST=127.0.0.1 LEN=34 .*PROTO=UDP SPT=[0-9]+ DPT=9999 LEN=14 ' /tmp/log.txt >/dev/null && echo LOG-OUT
`
			out := mustRunGuest(t, guestSpec{
				plat:   b.plat,
				image:  "alpine:3.20",
				argv:   []string{"sh", "-c", script},
				net:    gvx.NetModeNAT,
				netRaw: true,
			})
			requireContains(t, "guest output", out, "SAVE-OK\n", "LOG-IN\n", "LOG-OUT\n")
		})
	}
}
