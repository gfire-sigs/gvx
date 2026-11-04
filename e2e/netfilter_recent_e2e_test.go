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

// TestE2ENetfilterRecentSessionAffinity programs the session affinity rules of
// kube-proxy with the iptables "recent" match. A virtual address splits new
// clients between two backends with "statistic", and "recent" keeps each
// client on the backend of its first connection.
func TestE2ENetfilterRecentSessionAffinity(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			script := `set -e
apk add --no-cache iptables iptables-legacy socat >/dev/null
ipt="iptables-legacy -w"
socat TCP-LISTEN:8081,fork,reuseaddr SYSTEM:'echo b1' &
socat TCP-LISTEN:8082,fork,reuseaddr SYSTEM:'echo b2' &
for p in 8081 8082; do
  i=0; until socat -u TCP:127.0.0.1:$p - >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 50 ] && exit 1; sleep 0.1; done
done

# Without affinity both backends answer.
$ipt -t nat -N SPLIT
$ipt -t nat -A OUTPUT -d 10.96.0.2 -p tcp --dport 80 -j SPLIT
$ipt -t nat -A SPLIT -p tcp -m statistic --mode random --probability 0.5 -j DNAT --to-destination 127.0.0.1:8081
$ipt -t nat -A SPLIT -p tcp -j DNAT --to-destination 127.0.0.1:8082
seen=$(for i in $(seq 1 40); do socat -u TCP:10.96.0.2:80 -; done | sort -u | tr '\n' ' ')
echo "SPLIT $seen"

# With affinity one client stays on one backend.
$ipt -t nat -N SVC
$ipt -t nat -N SEP1
$ipt -t nat -N SEP2
$ipt -t nat -A OUTPUT -d 10.96.0.1 -p tcp --dport 80 -j SVC
$ipt -t nat -A SVC -m recent --name SEP1 --rcheck --seconds 10800 --reap --rsource -j SEP1
$ipt -t nat -A SVC -m recent --name SEP2 --rcheck --seconds 10800 --reap --rsource -j SEP2
$ipt -t nat -A SVC -m statistic --mode random --probability 0.5 -j SEP1
$ipt -t nat -A SVC -j SEP2
$ipt -t nat -A SEP1 -p tcp -m recent --set --name SEP1 --mask 255.255.255.255 --rsource -j DNAT --to-destination 127.0.0.1:8081
$ipt -t nat -A SEP2 -p tcp -m recent --set --name SEP2 --mask 255.255.255.255 --rsource -j DNAT --to-destination 127.0.0.1:8082
sticky=$(for i in $(seq 1 40); do socat -u TCP:10.96.0.1:80 -; done | sort -u | tr '\n' ' ')
echo "STICKY $sticky"
$ipt -t nat -S SVC | grep -c 'recent' | sed 's/^/RULES /'
$ipt -t nat -S SEP1 | grep -o -- '-m recent --set --name SEP1 --mask 255.255.255.255 --rsource' && echo SAVE-OK
`
			out := mustRunGuest(t, guestSpec{
				plat:   b.plat,
				image:  "alpine:3.20",
				argv:   []string{"sh", "-c", script},
				net:    gvx.NetModeNAT,
				netRaw: true,
			})
			requireContains(t, "guest output", out, "SPLIT b1 b2 \n", "RULES 2\n", "SAVE-OK\n")
			if !strings.Contains(out, "STICKY b1 \n") && !strings.Contains(out, "STICKY b2 \n") {
				t.Errorf("affinity clients reached more than one backend:\n%s", out)
			}
		})
	}
}
