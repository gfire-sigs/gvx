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

package e2e

import (
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
)

// ctnetlinkBulkScript fills the connection table with 5000 UDP flows. A DNAT
// rule tracks the datagrams that the probe sends to 127.0.0.2. The script lists
// the table with conntrack and with the Go library, which both need more than
// one answer datagram for 5000 flows. It deletes the flows with the library
// filter, creates them again, and deletes them with the filter of conntrack.
// Each listing line of conntrack holds the original destination port after
// "dst=127.0.0.2 sport=<n> dport=".
const ctnetlinkBulkScript = `set -e
apk add --no-cache iptables iptables-legacy conntrack-tools >/dev/null
ipt=iptables-legacy
$ipt -t nat -A OUTPUT -d 127.0.0.2 -p udp --dport 20000:29999 -j DNAT --to-destination 127.0.0.1
cp /workspace/ctprobe /usr/local/bin/ctprobe
chmod 755 /usr/local/bin/ctprobe
flows='-p udp --orig-dst 127.0.0.2'
list() {
  out=$(conntrack -L $flows 2>/dev/null)
  lines=$(echo "$out" | grep -c ' dst=127.0.0.2 ' || true)
  ports=$(echo "$out" | sed -n 's/.* dst=127.0.0.2 sport=[0-9]* dport=\([0-9]*\) .*/\1/p' | sort -u | wc -l)
  echo "$1 lines=$lines ports=$ports $(conntrack -L $flows 2>&1 >/dev/null)"
}
ctprobe bulk create
list CLI-LIST
ctprobe bulk list
ctprobe bulk delete
list CLI-LIST-AFTER-LIBRARY-DELETE
ctprobe bulk create
list CLI-LIST-AGAIN
echo "CLI-DELETE $(conntrack -D $flows 2>&1 >/dev/null)"
list CLI-LIST-AFTER-CLI-DELETE
`

// TestE2ENetfilterCtnetlinkDumpsMoreThan900Flows checks that the dump of the
// connection table has no size limit. A table with 5000 flows is more than five
// times what one answer of the former dump held. conntrack and the Go library
// list every flow, and both delete every flow with a filter.
func TestE2ENetfilterCtnetlinkDumpsMoreThan900Flows(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := runServicePathGuest(t, b, map[string]string{"ctprobe": acceptprog.BuildCtProbe(t, hostArch())}, ctnetlinkBulkScript)
			const tool = "conntrack v1.4.8 (conntrack-tools): "
			requireContains(t, "guest output", out,
				"PASS bulk-create\n",
				"CLI-LIST lines=5000 ports=5000 "+tool+"5000 flow entries have been shown.\n",
				"PASS bulk-list\n",
				"PASS bulk-delete\n",
				"CLI-LIST-AFTER-LIBRARY-DELETE lines=0 ports=0 "+tool+"0 flow entries have been shown.\n",
				"CLI-LIST-AGAIN lines=5000 ports=5000 "+tool+"5000 flow entries have been shown.\n",
				"CLI-DELETE "+tool+"5000 flow entries have been deleted.\n",
				"CLI-LIST-AFTER-CLI-DELETE lines=0 ports=0 "+tool+"0 flow entries have been shown.\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("a check failed; guest output:\n%s", out)
			}
		})
	}
}
