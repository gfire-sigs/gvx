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

package cgroup2fs

import (
	"bytes"
	"errors"
	"math"
	"runtime"
	"testing"
	"time"
	"weak"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// newTestCPU returns a cpu controller in the state that newController makes,
// below parent. The test removes the limit at its end, so the global count of
// limited nodes returns to its old value.
func newTestCPU(t *testing.T, parent *cpu) *cpu {
	t.Helper()
	cc := &cpu{c: &cgroup{}, parent: parent}
	cc.weight.Store(100)
	cc.maxUSec.Store(math.MaxInt64)
	cc.periodUSec.Store(100000)
	t.Cleanup(cc.releaseBandwidth)
	return cc
}

func requireLimit(t *testing.T, cc *cpu, wantQuota, wantPeriod time.Duration, wantLimited bool) {
	t.Helper()
	quota, period, limited := cc.bandwidthNode().Limit()
	if limited != wantLimited || (limited && (quota != wantQuota || period != wantPeriod)) {
		t.Errorf("budget limit = (%v, %v, %v), want (%v, %v, %v)", quota, period, limited, wantQuota, wantPeriod, wantLimited)
	}
}

func TestValidateCPUMaxFollowsLinuxLimits(t *testing.T) {
	tests := []struct {
		name    string
		quota   int64
		period  int64
		wantErr bool
	}{
		{"docker --cpus=0.5", 50000, 100000, false},
		{"no limit", cpuMaxUnlimited, 100000, false},
		{"shortest period", 1000, 1000, false},
		{"longest period", 500000, 1000000, false},
		{"quota above the period", 400000, 100000, false},
		{"period below 1 ms", 50000, 999, true},
		{"period above 1 s", 50000, 1000001, true},
		{"quota below 1 ms", 999, 100000, true},
		{"quota above the Linux maximum", 1 << 44, 100000, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCPUMax(tc.quota, tc.period)
			if tc.wantErr && !errors.Is(err, linuxerr.EINVAL) {
				t.Errorf("validateCPUMax(%d, %d) = %v, want EINVAL", tc.quota, tc.period, err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateCPUMax(%d, %d) = %v, want nil", tc.quota, tc.period, err)
			}
		})
	}
}

func TestBandwidthLimitsConvertsMicroseconds(t *testing.T) {
	quota, period := bandwidthLimits(50000, 100000)
	if quota != 50*time.Millisecond || period != 100*time.Millisecond {
		t.Errorf("bandwidthLimits(50000, 100000) = (%v, %v), want (50ms, 100ms)", quota, period)
	}
	quota, period = bandwidthLimits(cpuMaxUnlimited, 200000)
	if quota >= 0 || period != 200*time.Millisecond {
		t.Errorf("bandwidthLimits(max, 200000) = (%v, %v), want a negative quota and 200ms", quota, period)
	}
}

func TestSetMaxLimitsOnlyTheWrittenController(t *testing.T) {
	parent := newTestCPU(t, nil)
	child := newTestCPU(t, parent)

	if err := child.setMax(nil, 50000, 100000); err != nil {
		t.Fatalf("setMax: %v", err)
	}
	requireLimit(t, child, 50*time.Millisecond, 100*time.Millisecond, true)
	requireLimit(t, parent, 0, 0, false)
}

func TestSetMaxRejectsABadValueAndKeepsTheOldLimit(t *testing.T) {
	cc := newTestCPU(t, nil)
	if err := cc.setMax(nil, 50000, 100000); err != nil {
		t.Fatalf("setMax: %v", err)
	}
	if err := cc.setMax(nil, 500, 100000); !errors.Is(err, linuxerr.EINVAL) {
		t.Fatalf("setMax(500, 100000) = %v, want EINVAL", err)
	}
	requireLimit(t, cc, 50*time.Millisecond, 100*time.Millisecond, true)
	var buf bytes.Buffer
	if err := (&cpuMax{cc: cc}).Generate(context.Background(), &buf); err != nil || buf.String() != "50000 100000\n" {
		t.Errorf("cpu.max = %q (%v), want \"50000 100000\\n\"", buf.String(), err)
	}
}

func TestSetMaxMaxRemovesTheLimit(t *testing.T) {
	cc := newTestCPU(t, nil)
	if err := cc.setMax(nil, 50000, 100000); err != nil {
		t.Fatalf("setMax: %v", err)
	}
	if err := cc.setMax(nil, math.MaxInt64, 100000); err != nil {
		t.Fatalf("setMax(max): %v", err)
	}
	requireLimit(t, cc, 0, 0, false)
}

func TestBandwidthNodeLinksToTheNodeOfTheParentController(t *testing.T) {
	parent := newTestCPU(t, nil)
	mid := newTestCPU(t, parent)
	leaf := newTestCPU(t, mid)

	// The leaf node comes first. The chain must still end at the root.
	leafNode := leaf.bandwidthNode()
	if leaf.bandwidthNode() != leafNode {
		t.Error("bandwidthNode returned two nodes for one controller")
	}
	if err := parent.setMax(nil, 30000, 100000); err != nil {
		t.Fatalf("setMax: %v", err)
	}
	// A charge on the leaf reaches the limit of the ancestor.
	requireLimit(t, parent, 30*time.Millisecond, 100*time.Millisecond, true)
	if !leafHasAncestorLimit(leafNode) {
		t.Error("the node of the leaf does not see the limit of its grandparent")
	}
}

// leafHasAncestorLimit reports whether a node has a limit of its own or an
// ancestor, through the public interface of the budget.
func leafHasAncestorLimit(n *kernel.CPUBandwidth) bool {
	for ; n != nil; n = n.Parent() {
		if _, _, limited := n.Limit(); limited {
			return true
		}
	}
	return false
}

func TestSetMaxBeforeFirstUseAppliesTheStoredLimit(t *testing.T) {
	cc := newTestCPU(t, nil)
	cc.maxUSec.Store(20000)
	cc.periodUSec.Store(200000)
	requireLimit(t, cc, 20*time.Millisecond, 200*time.Millisecond, true)
}

func TestDetachRemovesTheLimitAndLaterWritesOnlyStore(t *testing.T) {
	cc := newTestCPU(t, nil)
	if err := cc.setMax(nil, 50000, 100000); err != nil {
		t.Fatalf("setMax: %v", err)
	}
	cc.detach()
	requireLimit(t, cc, 0, 0, false)
	if err := cc.setMax(nil, 40000, 100000); err != nil {
		t.Fatalf("setMax after detach: %v", err)
	}
	requireLimit(t, cc, 0, 0, false)
	if got := cc.maxUSec.Load(); got != 40000 {
		t.Errorf("stored quota = %d, want 40000", got)
	}
}

// +checklocksignore: the test owns the cgroup and no other goroutine reads it.
func TestRemovedCgroupReleasesItsLimit(t *testing.T) {
	cc := newTestCPU(t, nil)
	if err := cc.setMax(nil, 50000, 100000); err != nil {
		t.Fatalf("setMax: %v", err)
	}
	cc.c.ctrls[kernel.Cgroup2CPU] = cc
	cc.c.releaseCPUBandwidth()
	requireLimit(t, cc, 0, 0, false)
}

func TestCgroupBandwidthIsTheBudgetOfTheClosestCPUController(t *testing.T) {
	cc := newTestCPU(t, nil)
	owner := &cgroup{}
	owner.closestCtrls.Store(&ctrlSet{kernel.Cgroup2CPU: cc})
	if owner.CPUBandwidth() != cc.bandwidthNode() {
		t.Error("CPUBandwidth is not the budget of the closest cpu controller")
	}
	bare := &cgroup{}
	bare.closestCtrls.Store(&ctrlSet{})
	if bare.CPUBandwidth() != nil {
		t.Error("a cgroup without a cpu controller has a budget")
	}
}

func TestCPUStatUSecKeepsTheUsageAndClampsTheParts(t *testing.T) {
	usage1, user, sys := cpuStatUSec(usage.CPUStats{UserTime: 700 * time.Microsecond, SysTime: 300 * time.Microsecond})
	if usage1 != 1000 || user != 700 || sys != 300 {
		t.Errorf("cpuStatUSec = (%d, %d, %d), want (1000, 700, 300)", usage1, user, sys)
	}
	usage2, user, sys := cpuStatUSec(usage.CPUStats{UserTime: 1500 * time.Microsecond, SysTime: -500 * time.Microsecond})
	if usage2 != 1000 || user != 1000 || sys != 0 {
		t.Errorf("cpuStatUSec with a negative part = (%d, %d, %d), want (1000, 1000, 0)", usage2, user, sys)
	}
}

// +checklocksignore: the test owns the cgroups and no other goroutine reads them.
func TestRemovedCgroupAddsItsUsageToTheNearestParentController(t *testing.T) {
	parentCPU := newTestCPU(t, nil)
	parentCgroup := &cgroup{}
	parentCgroup.closestCtrls.Store(&ctrlSet{kernel.Cgroup2CPU: parentCPU})
	parentCPU.usage = usage.CPUStats{UserTime: 100 * time.Millisecond}

	child := newTestCPU(t, parentCPU)
	child.usage = usage.CPUStats{UserTime: 300 * time.Millisecond, SysTime: 50 * time.Millisecond}
	child.c.parent = parentCgroup
	child.c.ctrls[kernel.Cgroup2CPU] = child

	child.c.releaseCPUBandwidth()

	if got, want := parentCPU.usage.UserTime, 400*time.Millisecond; got != want {
		t.Errorf("parent user time = %v, want %v", got, want)
	}
	if got, want := parentCPU.usage.SysTime, 50*time.Millisecond; got != want {
		t.Errorf("parent system time = %v, want %v", got, want)
	}
	if child.usage != (usage.CPUStats{}) {
		t.Errorf("the removed cgroup keeps usage %+v", child.usage)
	}
}

// TestBandwidthKernelPrefersTheContextKernel checks which Kernel owns the
// bandwidth counters of a controller. Two sandboxes share one host process, so
// a controller must never take the Kernel of another filesystem.
func TestBandwidthKernelPrefersTheContextKernel(t *testing.T) {
	saved, other := &kernel.Kernel{}, &kernel.Kernel{}
	cc := newTestCPU(t, nil)
	if got := cc.bandwidthKernel(nil); got != nil {
		t.Errorf("bandwidthKernel without a filesystem = %p, want nil", got)
	}

	cc.c.fs = &filesystem{}
	cc.c.fs.memEnforcer.saveKernel = weak.Make(saved)
	if got := cc.bandwidthKernel(nil); got != saved {
		t.Errorf("bandwidthKernel without a context = %p, want the saved Kernel %p", got, saved)
	}
	ctx := context.WithValue(context.Background(), kernel.CtxKernel, other)
	if got := cc.bandwidthKernel(ctx); got != other {
		t.Errorf("bandwidthKernel with a context Kernel = %p, want %p", got, other)
	}
	runtime.KeepAlive(saved)
}
