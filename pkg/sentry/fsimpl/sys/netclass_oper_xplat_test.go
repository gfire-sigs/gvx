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

package sys

import (
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

var registerOperKind sync.Once

func TestOperStateOfAKindWithoutCarrierIsUnknownWhileUp(t *testing.T) {
	registerOperKind.Do(func() {
		netstack.RegisterLinkKind("test-sys-oper", netstack.LinkKind{
			NamePrefix: "ts",
			New: func(context.Context, *netstack.NewLinkRequest) (stack.LinkEndpoint, *syserr.Error) {
				return nil, syserr.ErrNotSupported
			},
			OperStateUnknown: true,
		})
	})
	for _, tc := range []struct {
		name string
		nic  inet.Interface
		want string
	}{
		{"kind up", inet.Interface{Kind: "test-sys-oper", Flags: linux.IFF_UP | linux.IFF_RUNNING}, "unknown"},
		{"kind down", inet.Interface{Kind: "test-sys-oper"}, "down"},
		{"ethernet up", inet.Interface{DeviceType: linux.ARPHRD_ETHER, Flags: linux.IFF_UP | linux.IFF_RUNNING}, "up"},
		{"loopback", inet.Interface{DeviceType: linux.ARPHRD_LOOPBACK, Flags: linux.IFF_UP | linux.IFF_RUNNING}, "unknown"},
	} {
		if got := linkOperState(tc.nic); got != tc.want {
			t.Errorf("%s: operstate = %q, want %q", tc.name, got, tc.want)
		}
	}
}
