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
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// rejectOutputScript installs the rule that kube-proxy installs for a service
// without endpoints: a REJECT with icmp-port-unreachable in the OUTPUT chain.
// The script connects to the rejected address three times, and then reads
// /proc/net/tcp, which needs the lock of every TCP endpoint of the guest.
const rejectOutputScript = `set -e
apk add --no-cache iptables iptables-legacy >/dev/null
iptables-legacy -A OUTPUT -p tcp -d 10.43.0.77 --dport 443 -j REJECT --reject-with icmp-port-unreachable
for i in 1 2 3; do
  start=$(date +%s)
  if nc -w 5 10.43.0.77 443 </dev/null >/dev/null 2>&1; then echo CONNECT-$i-SUCCEEDED; else echo CONNECT-$i-FAILED $(( $(date +%s) - start )); fi
done
wc -l < /proc/net/tcp | sed 's/^/PROC-NET-TCP-LINES /'
echo SCRIPT-DONE
`

// TestE2ENetfilterRejectOutputConnectFails checks that a TCP connect to an
// address that an OUTPUT REJECT rule refuses ends with a refusal at once. The
// ICMP error returns over the loopback link while the connect call still
// sends the SYN. Before the fix, the call never returned, and a read of
// /proc/net/tcp waited for the endpoint of that call without end.
func TestE2ENetfilterRejectOutputConnectFails(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", rejectOutputScript},
				net: gvx.NetModeNAT, netRaw: true, timeout: 3 * time.Minute,
			})
			for i := 1; i <= 3; i++ {
				prefix := "CONNECT-" + strconv.Itoa(i) + "-FAILED "
				_, rest, ok := strings.Cut(out, prefix)
				if !ok {
					t.Errorf("connect %d did not fail; output:\n%s", i, out)
					continue
				}
				if seconds, err := strconv.Atoi(strings.Fields(rest)[0]); err != nil || seconds > 2 {
					t.Errorf("connect %d failed after %q seconds, want a refusal within 2 seconds", i, strings.Fields(rest)[0])
				}
			}
			requireContains(t, "output", out, "PROC-NET-TCP-LINES ", "SCRIPT-DONE\n")
		})
	}
}
