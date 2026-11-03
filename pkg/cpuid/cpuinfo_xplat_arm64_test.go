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

//go:build arm64 && !linux

package cpuid

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecodeMIDR(t *testing.T) {
	for _, tc := range []struct {
		name string
		midr uint64
		want midrFields
	}{
		{"Apple under hvf", 0x610f0000, midrFields{implementer: 0x61}},
		{"whpx default Cortex-A53", 0x410fd030, midrFields{implementer: 0x41, part: 0xd03}},
		{"all fields set", 0x412fd0b3, midrFields{implementer: 0x41, variant: 2, part: 0xd0b, revision: 3}},
		{"architecture bits are dropped", 0x00f00000, midrFields{variant: 0xf}},
	} {
		if got := decodeMIDR(tc.midr); got != tc.want {
			t.Errorf("%s: decodeMIDR(%#x) = %+v, want %+v", tc.name, tc.midr, got, tc.want)
		}
	}
}

func TestBogoMIPS(t *testing.T) {
	for _, tc := range []struct {
		cntfrq uint64
		want   string
	}{
		{24_000_000, "48.00"},
		{1_000_000_000, "2000.00"},
		{19_200_000, "38.40"},
		{0, "0.00"},
	} {
		var b bytes.Buffer
		fs := FeatureSet{cpuFreqMHz: bogoMIPS(tc.cntfrq)}
		fs.WriteCPUInfoTo(0, 1, fs.CPUFreqMHz(), &b)
		if want := "BogoMIPS\t: " + tc.want + "\n"; !strings.Contains(b.String(), want) {
			t.Errorf("cntfrq %d: cpuinfo lacks %q:\n%s", tc.cntfrq, want, b.String())
		}
	}
}

func TestSetCPUInfoFillsEveryField(t *testing.T) {
	var fs FeatureSet
	setCPUInfo(&fs, 0x610f0000, 24_000_000)
	var b bytes.Buffer
	fs.WriteCPUInfoTo(0, 1, fs.CPUFreqMHz(), &b)
	for _, want := range []string{
		"BogoMIPS\t: 48.00\n",
		"CPU implementer\t: 0x61\n",
		"CPU architecture\t: 8\n",
		"CPU variant\t: 0x0\n",
		"CPU part\t: 0x0\n",
		"CPU revision\t: 0\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("cpuinfo lacks %q:\n%s", want, b.String())
		}
	}
}

// TestHostCPUInfoIsFilledAtInit checks the real host: the package init must
// fill the fields without a call to Initialize.
func TestHostCPUInfoIsFilledAtInit(t *testing.T) {
	fs := HostFeatureSet()
	if got := fs.CPUArchitecture(); got != 8 {
		t.Errorf("CPUArchitecture() = %d, want 8", got)
	}
	if fs.CPUImplementer() == 0 {
		t.Error("CPUImplementer() = 0, want the implementer of MIDR_EL1")
	}
	if fs.cpuFreqMHz <= 0 {
		t.Errorf("BogoMIPS = %v, want a positive value", fs.cpuFreqMHz)
	}
	if want := decodeMIDR(platformMIDR()); fs.cpuImplHex != want.implementer || fs.cpuPartHex != want.part {
		t.Errorf("implementer/part = %#x/%#x, want %#x/%#x", fs.cpuImplHex, fs.cpuPartHex, want.implementer, want.part)
	}
}
