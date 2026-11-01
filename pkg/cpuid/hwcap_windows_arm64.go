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

//go:build windows && arm64

package cpuid

import (
	"maps"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// centralProcessorKey holds the ID registers that Windows publishes for
// processor 0. Each value name encodes the op1, CRn, CRm, and op2 fields of
// its register, so "CP 4030" is ID_AA64ISAR0_EL1.
const centralProcessorKey = `HARDWARE\DESCRIPTION\System\CentralProcessor\0`

// processorFeatureFlags maps IsProcessorFeaturePresent flags to feature names.
// The Armv8-A base profile includes floating point and Advanced SIMD, so
// PF_ARM_V8_INSTRUCTIONS_AVAILABLE reports both.
var processorFeatureFlags = []struct {
	flag     uint32
	features []string
}{
	{windows.PF_ARM_V8_INSTRUCTIONS_AVAILABLE, []string{"FEAT_FP", "FEAT_AdvSIMD"}},
	{windows.PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE, []string{"FEAT_AES", "FEAT_PMULL", "FEAT_SHA1", "FEAT_SHA256"}},
	{windows.PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE, []string{"FEAT_CRC32"}},
	{windows.PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE, []string{"FEAT_LSE"}},
	{windows.PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE, []string{"FEAT_DotProd"}},
	{windows.PF_ARM_V82_FP16_INSTRUCTIONS_AVAILABLE, []string{"FEAT_FP16"}},
	{windows.PF_ARM_V82_I8MM_INSTRUCTIONS_AVAILABLE, []string{"FEAT_I8MM"}},
	{windows.PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE, []string{"FEAT_JSCVT"}},
	{windows.PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE, []string{"FEAT_LRCPC"}},
	{windows.PF_ARM_LSE2_AVAILABLE, []string{"FEAT_LSE2"}},
	{windows.PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE, []string{"FEAT_SHA3"}},
	{windows.PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE, []string{"FEAT_SHA512"}},
	{windows.PF_ARM_V86_BF16_INSTRUCTIONS_AVAILABLE, []string{"FEAT_BF16"}},
}

// platformHWCap derives AT_HWCAP on Windows arm64 from the host, then limits
// it to the features that the guest ID registers report.
//
// whpx serves the guest ID registers from hvcommon.DefaultIDRegisters, which
// do not read the host. The limit keeps AT_HWCAP consistent with those
// registers. It follows the registers automatically if whpx serves host
// values later.
func platformHWCap() (hwCap, error) {
	host := processorFeatures()
	maps.Copy(host, hostIDFeatures())
	guest := guestFeatures(hvcommon.DefaultIDRegisters())
	return hwcapFromFeatures(restrictFeatures(host, guest)), nil
}

// processorFeatures returns the features that IsProcessorFeaturePresent
// reports.
func processorFeatures() map[string]bool {
	features := make(map[string]bool)
	for _, pf := range processorFeatureFlags {
		if !windows.IsProcessorFeaturePresent(pf.flag) {
			continue
		}
		for _, name := range pf.features {
			features[name] = true
		}
	}
	return features
}

// hostIDFeatures returns the features that the host ID registers report. It
// returns nil when Windows does not publish the registers. The processor
// features then remain the only host source.
func hostIDFeatures() map[string]bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, centralProcessorKey, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer func() {
		if err := k.Close(); err != nil {
			log.Warningf("Could not close registry key %s: %v", centralProcessorKey, err)
		}
	}()

	var regs [idRegCount]uint64
	for _, r := range []struct {
		name string
		reg  int
	}{
		{"CP 4020", idRegPFR0},
		{"CP 4030", idRegISAR0},
		{"CP 4031", idRegISAR1},
	} {
		v, _, err := k.GetIntegerValue(r.name)
		if err != nil {
			return nil
		}
		regs[r.reg] = v
	}
	// ID_AA64MMFR2_EL1 is not published here, so the zero value reports no
	// FEAT_LSE2. The processor features supply that bit instead.
	return featuresFromIDRegisters(regs)
}

// guestFeatures returns the features that the emulated ID registers report
// to the guest. It returns nil when an emulated register is unavailable, so
// no feature is advertised.
func guestFeatures(ids hvcommon.IDRegisters) map[string]bool {
	var regs [idRegCount]uint64
	for _, r := range []struct {
		crm, op2 uint32
		reg      int
	}{
		{4, 0, idRegPFR0},
		{6, 0, idRegISAR0},
		{6, 1, idRegISAR1},
		{7, 2, idRegMMFR2},
	} {
		v, ok := ids.EmulateSysRegRead(hvcommon.SysRegISS{Read: true, Op0: 3, CRm: r.crm, Op2: r.op2})
		if !ok {
			return nil
		}
		regs[r.reg] = v
	}
	return featuresFromIDRegisters(regs)
}
