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

package cpuid

// RestrictXSAVE returns a copy of fs for guests that run with xcr0 in XCR0.
// CPUID leaf 0xD reports xcr0 as the supported user state components, the
// sub-leaves of the other user components disappear, and every feature in
// hidden reads as absent. The Sentry derives the signal frame xfeatures, the
// sigreturn checks, and /proc/cpuinfo from the result.
func (fs FeatureSet) RestrictXSAVE(xcr0 uint64, hidden ...Feature) FeatureSet {
	s := fs.ToStatic()
	for _, f := range hidden {
		s.Remove(f)
	}
	in := In{Eax: uint32(xSaveInfo)}
	out := s[in]
	out.Eax, out.Edx = uint32(xcr0), uint32(xcr0>>32)
	s[in] = out
	for i := uint32(2); i < xSaveInfoNumLeaves; i++ {
		sub := In{Eax: uint32(xSaveInfo), Ecx: i}
		// ECX bit 0 marks a supervisor component, which XCR0 never names.
		if xcr0&(1<<i) == 0 && s[sub].Ecx&1 == 0 {
			delete(s, sub)
		}
	}
	rfs := s.ToFeatureSet()
	rfs.hwCap = fs.hwCap
	return rfs
}
