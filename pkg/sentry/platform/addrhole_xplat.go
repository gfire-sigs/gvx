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

package platform

import "z.gfire.dev/gvx/pkg/hostarch"

// AddressHolePlatform is an optional interface of a Platform. A platform
// implements it when its guest address range [MinUserAddress, MaxUserAddress)
// has gaps that the host owns, so that no guest mapping can use them. The
// guest runs inside a host process, and the host process keeps its own
// structures in the gaps.
type AddressHolePlatform interface {
	// UserAddressHoles returns the gaps inside the guest address range, in
	// ascending order. The gaps do not overlap, and none is empty. A platform
	// without gaps returns no ranges. The result does not change while the
	// platform runs.
	UserAddressHoles() []hostarch.AddrRange
}
