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

//go:build darwin && arm64

package cpuid

import (
	"z.gfire.dev/gvx/internal/xsys/unix"
)

// platformHWCap derives AT_HWCAP and AT_HWCAP2 from the hw.optional sysctl
// keys that the Darwin kernel publishes for each Arm feature.
//
// The guest reads its ID registers through hvf, which returns the host values
// with the PAC, SVE, MTE, SME, and MPAM fields hidden. None of the features in
// the HWCAP tables uses those fields, so the host bits are a subset of what
// the guest reads.
func platformHWCap() (hwCap, error) {
	features := make(map[string]bool)
	for _, entries := range [][]hwcapEntry{hwcap1Entries, hwcap2Entries} {
		for _, e := range entries {
			features[e.feature] = hostFeatureSysctl(e.feature)
		}
	}
	return hwcapFromFeatures(features), nil
}

// hostFeatureSysctl reports whether the kernel publishes feature as present.
// A key that the kernel does not publish reports the feature as absent.
func hostFeatureSysctl(feature string) bool {
	v, err := unix.SysctlUint32(sysctlKey(feature))
	return err == nil && v != 0
}

// sysctlKey returns the hw.optional key that reports feature.
func sysctlKey(feature string) string {
	switch feature {
	case "FEAT_FP":
		return "hw.optional.floatingpoint"
	case "FEAT_AdvSIMD":
		return "hw.optional.arm.AdvSIMD"
	default:
		return "hw.optional.arm." + feature
	}
}
