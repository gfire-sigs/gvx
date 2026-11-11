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

package tcpip_test

import (
	"bytes"
	"context"
	"testing"

	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
)

func TestRouteAttrsStateRoundTrip(t *testing.T) {
	dest, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{10, 244, 2, 0}),
		tcpip.MaskFromBytes([]byte{255, 255, 255, 0}),
	)
	if err != nil {
		t.Fatalf("NewSubnet: %v", err)
	}

	orig := tcpip.Route{
		RouteAttrs: tcpip.RouteAttrs{
			Table:    100,
			Metric:   250,
			Protocol: 4,
			Scope:    200,
			ScopeSet: true,
			Type:     tcpip.RouteTypeProhibit,
			TOS:      0x10,
			Flags:    0x100,
		},
		Destination: dest,
		Gateway:     tcpip.AddrFrom4([4]byte{10, 244, 0, 1}),
		NIC:         2,
		SourceHint:  tcpip.AddrFrom4([4]byte{10, 244, 0, 10}),
		MTU:         1420,
	}

	var buf bytes.Buffer
	ctx := context.Background()
	if _, err := state.Save(ctx, &buf, &orig); err != nil {
		t.Fatalf("state.Save Route: %v", err)
	}

	var restored tcpip.Route
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load Route: %v", err)
	}

	if restored.RouteAttrs != orig.RouteAttrs {
		t.Fatalf("restored.RouteAttrs = %+v, want %+v", restored.RouteAttrs, orig.RouteAttrs)
	}
	if got := restored.TableID(); got != 100 {
		t.Fatalf("restored.TableID() = %d, want 100", got)
	}
	if got := restored.EffectiveScope(true); got != 200 {
		t.Fatalf("restored.EffectiveScope(true) = %d, want 200", got)
	}
	if got := restored.RouteType(); got != tcpip.RouteTypeProhibit || !got.IsReject() {
		t.Fatalf("restored.RouteType() = %d (IsReject=%v), want %d (true)", got, got.IsReject(), tcpip.RouteTypeProhibit)
	}
	if !restored.Destination.Equal(orig.Destination) {
		t.Fatalf("restored.Destination = %s, want %s", restored.Destination, orig.Destination)
	}
	if restored.Gateway != orig.Gateway || restored.NIC != orig.NIC || restored.SourceHint != orig.SourceHint || restored.MTU != orig.MTU {
		t.Fatalf("restored Route = %+v, want %+v", restored, orig)
	}
}
