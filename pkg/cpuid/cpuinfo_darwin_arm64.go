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

import "z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"

// platformMIDR returns the MIDR_EL1 value of the guest on this host. The hvf
// backend writes hvcommon.HVFMIDREL1 to every vCPU.
func platformMIDR() uint64 { return hvcommon.HVFMIDREL1 }
