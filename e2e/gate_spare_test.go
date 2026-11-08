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

//go:build darwin || windows || linux

package e2e

import (
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
)

// spareProbeChecks lists the checks of the guest spareprobe.
var spareProbeChecks = []string{
	"remap-reads-zero",
	"new-neighbor",
	"guard-gains-access",
	"dontneed-reads-zero",
	"fork-isolation",
}

// TestE2ESystrapSparePages runs a guest that maps single pages in one 16 KB
// block and changes them with munmap, mmap, mprotect, MADV_DONTNEED, and fork.
// The Linux systrap engine on a host with 16 KB pages maps such a block
// directly. It holds the unused pages of the block as spare pages.
// GVX_SYSTRAP_SUBBLOCKS=1 runs that code on a host with 4 KB pages. The guest
// and the guest kernel must agree on every byte, as on Linux, so every backend
// must pass every check.
func TestE2ESystrapSparePages(t *testing.T) {
	runCPUProbe(t, acceptprog.BuildSpareProbe(t, hostArch()), "spareprobe", "SPAREPROBE-OK", spareProbeChecks)
}
