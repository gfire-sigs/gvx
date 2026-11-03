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

package whpx

import (
	"bytes"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/cpuid"
)

// testHostFeatures is a host with AVX-512, MPX, protection keys, and AMX, as
// the CPUID of the Windows host reports them to the Sentry.
func testHostFeatures() cpuid.FeatureSet {
	s := cpuid.Static{}
	for _, f := range []cpuid.Feature{
		cpuid.X86FeatureXSAVE, cpuid.X86FeatureOSXSAVE, cpuid.X86FeatureXSAVEOPT, cpuid.X86FeatureXSAVES,
		cpuid.X86FeatureSSE2, cpuid.X86FeatureAVX, cpuid.X86FeatureF16C, cpuid.X86FeatureFMA,
		cpuid.X86FeatureAVX2, cpuid.X86FeatureAVX512F, cpuid.X86FeatureAVX512VL, cpuid.X86FeatureMPX,
		cpuid.X86FeaturePKU, cpuid.X86FeatureOSPKE, cpuid.X86FeatureVAES,
	} {
		f.Set(s)
	}
	const hostXCR0 = xcr0Legacy | xcr0AVX | 1<<3 | 1<<4 | xcr0AVX512 | 1<<9
	leaf := cpuid.In{Eax: 0xD}
	out := s.Query(leaf)
	out.Eax = uint32(hostXCR0)
	s.Set(leaf, out)
	for _, c := range []struct{ id, size, offset uint32 }{{2, 256, 576}, {3, 64, 960}, {4, 64, 1024}, {5, 64, 1088}, {6, 512, 1152}, {7, 1024, 1664}, {9, 8, 2688}} {
		s.Set(cpuid.In{Eax: 0xD, Ecx: c.id}, cpuid.Out{Eax: c.size, Ebx: c.offset})
	}
	return s.ToFeatureSet()
}

// cpuinfoFlags returns the flags line that the Sentry writes into
// /proc/cpuinfo for fs.
func cpuinfoFlags(fs cpuid.FeatureSet) string {
	var b bytes.Buffer
	fs.WriteCPUInfoTo(0, 1, fs.CPUFreqMHz(), &b)
	for line := range strings.Lines(b.String()) {
		if strings.HasPrefix(line, "flags") {
			return " " + strings.TrimSpace(line[strings.Index(line, ":")+1:]) + " "
		}
	}
	return ""
}

func TestGuestFeatureSetMatchesTheAVX512Partition(t *testing.T) {
	p := newTestPlatform(t, newFakeBackend(), Options{xsaveLayout: testXsaveLayout(), fpLimit: testFPLimit})
	gfs := p.GuestFeatureSet(testHostFeatures())
	if got := gfs.ValidXCR0Mask(); got != p.vec.xcr0 {
		t.Errorf("ValidXCR0Mask = %#x, want the guest XCR0 %#x: signal frames and sigreturn would name other components", got, p.vec.xcr0)
	}
	flags := cpuinfoFlags(gfs)
	for _, want := range []string{"avx", "avx2", "fma", "f16c", "avx512f", "avx512vl", "vaes", "xsaveopt", "xsaves"} {
		if !strings.Contains(flags, " "+want+" ") {
			t.Errorf("/proc/cpuinfo flags lack %q, which the guest can use: %s", want, flags)
		}
	}
	for _, hidden := range []string{"mpx", "pku", "ospke"} {
		if strings.Contains(flags, " "+hidden+" ") {
			t.Errorf("/proc/cpuinfo flags list %q, which the guest cannot use: %s", hidden, flags)
		}
	}
}

func TestGuestFeatureSetWithoutAVXHidesEveryVEXFeature(t *testing.T) {
	fb := newFakeBackend()
	fb.feats.xsaveFeatures = testXsaveCapability &^ (xsaveAVXFeatures | xsaveAVX512Features)
	p := newTestPlatform(t, fb, Options{xsaveLayout: testXsaveLayout(), fpLimit: testFPLimit})
	gfs := p.GuestFeatureSet(testHostFeatures())
	if got := gfs.ValidXCR0Mask(); got != xcr0Legacy {
		t.Errorf("ValidXCR0Mask = %#x, want x87 and SSE only", got)
	}
	flags := cpuinfoFlags(gfs)
	for _, hidden := range []string{"avx", "avx2", "fma", "f16c", "avx512f", "vaes"} {
		if strings.Contains(flags, " "+hidden+" ") {
			t.Errorf("/proc/cpuinfo flags list %q on a partition without AVX: %s", hidden, flags)
		}
	}
	if !strings.Contains(flags, " xsave ") {
		t.Errorf("/proc/cpuinfo flags lack xsave: %s", flags)
	}
}

func TestNewConfiguresThePartitionWithTheSelectedFeatures(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{xsaveLayout: testXsaveLayout(), fpLimit: testFPLimit})
	if p.vec.xcr0 != xcr0Legacy|xcr0AVX|xcr0AVX512 {
		t.Errorf("XCR0 = %#x, want x87, SSE, AVX and AVX-512", p.vec.xcr0)
	}
	if hidden := fb.cfg.xsaveFeatures & testHiddenFeatures; hidden != 0 {
		t.Errorf("ProcessorXsaveFeatures %#x exposes %#x, whose state the Sentry lacks", fb.cfg.xsaveFeatures, hidden)
	}
	if fb.cfg.clearProcFeatures != 0 {
		t.Errorf("an AVX partition hides ProcessorFeatures %#x", fb.cfg.clearProcFeatures)
	}
	if len(fb.vps) != 0 || fb.created != 1 {
		t.Errorf("after New, %d processors exist and %d were created; want the probe processor deleted", len(fb.vps), fb.created)
	}
}

func TestNewFailsWhenThePartitionDropsAnEnabledFeature(t *testing.T) {
	fb := newFakeBackend()
	fb.dropXsave = xsaveFeatAvx512
	if _, err := newPlatform(fb, Options{processors: 2, xsaveLayout: testXsaveLayout(), fpLimit: testFPLimit}); err == nil {
		t.Fatal("New accepted a partition without the AVX-512 feature that XCR0 enables")
	}
	if fb.partitionOpen {
		t.Error("the partition stays open after the failure")
	}
}

func TestNewFailsWhenTheXsaveStateLacksAnXCR0Component(t *testing.T) {
	fb := newFakeBackend()
	fb.xcompBV = xcr0Legacy | xcr0AVX
	if _, err := newPlatform(fb, Options{processors: 2, xsaveLayout: testXsaveLayout(), fpLimit: testFPLimit}); err == nil {
		t.Fatal("New accepted an XSAVE state without the AVX-512 components of XCR0")
	}
	if fb.partitionOpen || len(fb.vps) != 0 {
		t.Errorf("after the failure the partition is open: %v, %d processors remain", fb.partitionOpen, len(fb.vps))
	}
}
