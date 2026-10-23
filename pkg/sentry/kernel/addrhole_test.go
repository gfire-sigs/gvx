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

package kernel

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

type holePlatform struct {
	platform.Platform
	hole hostarch.AddrRange
}

func (p holePlatform) UserAddressHole() hostarch.AddrRange { return p.hole }

type plainPlatform struct{ platform.Platform }

// TestKernelForwardsThePlatformAddressHole checks the view that the memory
// manager has. It takes the kernel as its platform, so a hole that only the
// concrete platform reports would stay invisible, and a guest could map
// memory in it.
func TestKernelForwardsThePlatformAddressHole(t *testing.T) {
	hole := hostarch.AddrRange{Start: 0x7ffe0000, End: 0x1000_0000_0000}
	var p platform.Platform = (&Kernel{Platform: holePlatform{hole: hole}})
	hp, ok := p.(platform.AddressHolePlatform)
	if !ok {
		t.Fatal("the kernel does not implement platform.AddressHolePlatform")
	}
	if got := hp.UserAddressHole(); got != hole {
		t.Errorf("UserAddressHole() = %v, want the hole of the platform, %v", got, hole)
	}

	plain := &Kernel{Platform: plainPlatform{}}
	if got := plain.UserAddressHole(); got.Length() != 0 {
		t.Errorf("UserAddressHole() of a platform without a hole = %v, want an empty range", got)
	}
}
