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

package hvf

import (
	"testing"

	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// TestGuestMIDRMatchesCPUInfo verifies that /proc/cpuinfo lists the MIDR_EL1
// value that a guest reads. Both come from cpuid.HVFMIDR, so the guest value
// does not depend on the Apple chip of the host.
func TestGuestMIDRMatchesCPUInfo(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnMrsMIDR, insnSVC0)
	if sig, _, err := g.switchOnce(); sig != nil || err != nil {
		t.Fatalf("MRS MIDR_EL1: Switch = (%v, %v), want a syscall", sig, err)
	}
	midr := g.regs().Regs[0]
	if midr != hvcommon.HVFMIDREL1 {
		t.Fatalf("guest MIDR_EL1 = %#x, want hvcommon.HVFMIDREL1 = %#x", midr, hvcommon.HVFMIDREL1)
	}
	fs := cpuid.HostFeatureSet()
	if got, want := fs.CPUImplementer(), uint8(midr>>24); got != want {
		t.Errorf("CPUImplementer() = %#x, want %#x", got, want)
	}
	if got, want := fs.CPUVariant(), uint8(midr>>20&0xf); got != want {
		t.Errorf("CPUVariant() = %#x, want %#x", got, want)
	}
	if got, want := fs.CPUPartnum(), uint16(midr>>4&0xfff); got != want {
		t.Errorf("CPUPartnum() = %#x, want %#x", got, want)
	}
	if got, want := fs.CPURevision(), uint8(midr&0xf); got != want {
		t.Errorf("CPURevision() = %#x, want %#x", got, want)
	}
}
