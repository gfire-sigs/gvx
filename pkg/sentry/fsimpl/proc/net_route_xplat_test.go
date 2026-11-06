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

package proc

import (
	"bytes"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/inet"
)

// TestNetRouteListsTheTableMainWithMetrics checks /proc/net/route, which lists
// the table main only and prints the priority of a route as its metric. The
// default route of the table 51820 that wg-quick adds must not show as a
// second default route.
func TestNetRouteListsTheTableMainWithMetrics(t *testing.T) {
	s := inet.NewTestStack()
	s.InterfacesMap[2] = inet.Interface{Name: "eth0"}
	s.InterfacesMap[3] = inet.Interface{Name: "wg0"}
	s.RouteList = []inet.Route{
		{Family: linux.AF_INET, Table: linux.RT_TABLE_MAIN, Type: linux.RTN_UNICAST, DstAddr: []byte{0, 0, 0, 0}, GatewayAddr: []byte{10, 0, 2, 2}, OutputInterface: 2, Priority: 100},
		{Family: linux.AF_INET, Table: 51820, Type: linux.RTN_UNICAST, DstAddr: []byte{0, 0, 0, 0}, OutputInterface: 3},
	}
	var buf bytes.Buffer
	if err := (&netRouteData{stack: s}).Generate(context.Background(), &buf); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("/proc/net/route has %d lines, want the header and one route:\n%s", len(lines), buf.String())
	}
	f := strings.Fields(lines[1])
	if f[0] != "eth0" || f[6] != "100" {
		t.Errorf("route line = %q, want the interface eth0 and the metric 100", lines[1])
	}
}
