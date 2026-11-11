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
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// wireguardDeviceGoroutines returns the number of goroutines that belong to
// wireguard-go devices in this process.
func wireguardDeviceGoroutines() int {
	buf := make([]byte, 1<<24)
	buf = buf[:runtime.Stack(buf, true)]
	return strings.Count(string(buf), "golang.zx2c4.com/wireguard/device.(*Device).")
}

// TestE2EWireGuardDeviceEndsWithItsSandbox checks that the wireguard-go device
// of a link stops when the sandbox ends. One guest creates a link in its root
// network namespace, and another creates a link in a namespace that it adds.
// Both links have a peer with a keepalive, so the device keeps sending
// handshakes. The device goroutines of the process must go away after Close.
func TestE2EWireGuardDeviceEndsWithItsSandbox(t *testing.T) {
	const script = `set -e
apk add --no-cache wireguard-tools iproute2 >/dev/null
umask 077
wg genkey > /tmp/key
peer=$(wg genkey | wg pubkey)
setup='ip link add wg0 type wireguard
wg set wg0 private-key /tmp/key listen-port 0 peer '$peer' endpoint 192.0.2.7:51820 allowed-ips 10.77.0.2/32 persistent-keepalive 1
ip addr add 10.77.0.1/24 dev wg0
ip link set wg0 up'
case "$WHERE" in
root) sh -c "$setup" ;;
netns) ip netns add n1; ip netns exec n1 sh -c "$setup" ;;
esac
echo LINK-UP
`
	for _, b := range gateBackends() {
		for _, where := range []string{"root", "netns"} {
			t.Run(b.name+"/"+where, func(t *testing.T) {
				requireFixedAddressBackend(t, b)
				requireRegistry(t)
				before := wireguardDeviceGoroutines()
				out := mustRunGuest(t, guestSpec{
					plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script},
					net: gvx.NetModeNAT, netRaw: true, envv: []string{"WHERE=" + where},
				})
				requireContains(t, "guest output", out, "LINK-UP")
				// The sandbox is closed. The device stops in bounded time.
				deadline := time.Now().Add(20 * time.Second)
				for {
					after := wireguardDeviceGoroutines()
					if after <= before {
						return
					}
					if time.Now().After(deadline) {
						t.Fatalf("%d wireguard-go goroutines before the guest and %d after Close, want no more than before", before, after)
					}
					runtime.GC()
					runtime.Gosched()
				}
			})
		}
	}
}
