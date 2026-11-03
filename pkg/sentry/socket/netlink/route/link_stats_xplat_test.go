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

package route

import (
	"encoding/binary"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/inet"
)

func TestLinkStats64FollowsTheKernelLayout(t *testing.T) {
	// /proc/net/dev order: receive bytes, packets, errors, dropped, ..., multicast,
	// then transmit bytes, packets, errors, dropped.
	var dev inet.StatDev
	dev[0], dev[1], dev[2], dev[3], dev[7] = 1000, 10, 2, 3, 4
	dev[8], dev[9], dev[10], dev[11] = 2000, 20, 5, 6

	b := linkStats64(dev)
	if len(b) != 24*8 {
		t.Fatalf("len(linkStats64) = %d, want 192, the size of struct rtnl_link_stats64", len(b))
	}
	field := func(i int) uint64 { return binary.NativeEndian.Uint64(b[i*8:]) }
	// struct rtnl_link_stats64 starts with rx_packets, tx_packets, rx_bytes,
	// tx_bytes, rx_errors, tx_errors, rx_dropped, tx_dropped, multicast.
	for i, want := range []uint64{10, 20, 1000, 2000, 2, 5, 3, 6, 4} {
		if got := field(i); got != want {
			t.Errorf("rtnl_link_stats64 field %d = %d, want %d", i, got, want)
		}
	}
	for i := 9; i < 24; i++ {
		if got := field(i); got != 0 {
			t.Errorf("rtnl_link_stats64 field %d = %d, want 0 for a counter that the stack lacks", i, got)
		}
	}
}
