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

//go:build linux

package platform

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestMeasureMMapMinAddrMatchesTheKernel compares the measured minimum with
// the value that the kernel publishes, on a host that lets the test read it.
func TestMeasureMMapMinAddrMatchesTheKernel(t *testing.T) {
	if hasCapSysRawIO(t) {
		t.Skip("CAP_SYS_RAWIO lets this process map below vm.mmap_min_addr")
	}
	b, err := os.ReadFile("/proc/sys/vm/mmap_min_addr")
	if err != nil {
		t.Skipf("the host denies the read of vm.mmap_min_addr: %v", err)
	}
	published, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	page := uint64(os.Getpagesize())
	want := max((published+page-1)/page*page, page)
	want = min(want, probeMMapMinAddrLimit)
	if got := measureMMapMinAddr(); got != want {
		t.Errorf("measureMMapMinAddr() = %#x, want %#x (vm.mmap_min_addr = %d)", got, want, published)
	}
}

// hasCapSysRawIO reports whether the effective capabilities of this process
// hold CAP_SYS_RAWIO (bit 17), which exempts it from vm.mmap_min_addr.
func hasCapSysRawIO(t *testing.T) bool {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		if hex, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			return caps&(1<<17) != 0
		}
	}
	return false
}
