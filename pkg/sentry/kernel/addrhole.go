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
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// UserAddressHole implements platform.AddressHolePlatform. The memory manager
// takes the kernel as its platform, and the kernel embeds the platform as an
// interface. The optional methods of the concrete platform are therefore not
// visible through the kernel, so the kernel forwards the address hole.
func (k *Kernel) UserAddressHole() hostarch.AddrRange {
	if hp, ok := k.Platform.(platform.AddressHolePlatform); ok {
		return hp.UserAddressHole()
	}
	return hostarch.AddrRange{}
}
