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
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

type holePlatform struct {
	platform.Platform
	holes []hostarch.AddrRange
}

func (p holePlatform) UserAddressHoles() []hostarch.AddrRange { return p.holes }

type plainPlatform struct{ platform.Platform }

// TestKernelForwardsThePlatformAddressHoles checks the view that the memory
// manager has. It takes the kernel as its platform, so holes that only the
// concrete platform reports would stay invisible, and a guest could map
// memory in them.
func TestKernelForwardsThePlatformAddressHoles(t *testing.T) {
	holes := []hostarch.AddrRange{
		{Start: 0x7ffe0000, End: 0x1_0000_0000},
		{Start: 0x10_0000_0000, End: 0x1000_0000_0000},
	}
	var p platform.Platform = (&Kernel{Platform: holePlatform{holes: holes}})
	hp, ok := p.(platform.AddressHolePlatform)
	if !ok {
		t.Fatal("the kernel does not implement platform.AddressHolePlatform")
	}
	if got := hp.UserAddressHoles(); !slices.Equal(got, holes) {
		t.Errorf("UserAddressHoles() = %v, want the holes of the platform, %v", got, holes)
	}

	plain := &Kernel{Platform: plainPlatform{}}
	if got := plain.UserAddressHoles(); len(got) != 0 {
		t.Errorf("UserAddressHoles() of a platform without holes = %v, want none", got)
	}
}
