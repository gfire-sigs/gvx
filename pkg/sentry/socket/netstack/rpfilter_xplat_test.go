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

package netstack

import (
	"errors"
	"math"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/link/veth"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// requireRPFilter checks the file value of a link and the value that the
// reverse path check uses.
func requireRPFilter(t *testing.T, s *Stack, id tcpip.NICID, wantFile, wantEffective int32) {
	t.Helper()
	got, err := s.LinkRPFilter(int32(id))
	if err != nil {
		t.Fatalf("LinkRPFilter(%d): %v", id, err)
	}
	if got != wantFile {
		t.Errorf("conf/<link %d>/rp_filter = %d, want %d", id, got, wantFile)
	}
	if eff := s.EffectiveRPFilter(id); eff != wantEffective {
		t.Errorf("EffectiveRPFilter(%d) = %d, want %d", id, eff, wantEffective)
	}
}

func TestRPFilterStartsAtZero(t *testing.T) {
	s := ethtoolStack(t, "veth")
	if s.RPFilterAll() != 0 || s.RPFilterDefault() != 0 {
		t.Errorf("all=%d default=%d, want 0 and 0", s.RPFilterAll(), s.RPFilterDefault())
	}
	requireRPFilter(t, s, 1, 0, 0)
}

func TestRPFilterTakesTheLargerOfAllAndTheLink(t *testing.T) {
	s := ethtoolStack(t, "veth")
	s.SetRPFilterAll(1)
	requireRPFilter(t, s, 1, 0, 1)
	if err := s.SetLinkRPFilter(1, 2); err != nil {
		t.Fatal(err)
	}
	requireRPFilter(t, s, 1, 2, 2)
	s.SetRPFilterAll(2)
	if err := s.SetLinkRPFilter(1, 1); err != nil {
		t.Fatal(err)
	}
	requireRPFilter(t, s, 1, 1, 2)
	// The link file does not follow the all value.
	s.SetRPFilterAll(0)
	requireRPFilter(t, s, 1, 1, 1)
}

func TestRPFilterAllChangesNoLink(t *testing.T) {
	s := ethtoolStack(t, "veth", "bridge")
	s.SetRPFilterAll(1)
	if got := s.RPFilterDefault(); got != 0 {
		t.Errorf("default = %d after a write to all, want 0", got)
	}
	for id := tcpip.NICID(1); id <= 2; id++ {
		if got, _ := s.LinkRPFilter(int32(id)); got != 0 {
			t.Errorf("link %d = %d after a write to all, want 0", id, got)
		}
	}
}

func TestRPFilterDefaultReachesLinksWithoutAValue(t *testing.T) {
	s := ethtoolStack(t, "veth", "bridge")
	if err := s.SetLinkRPFilter(2, 1); err != nil {
		t.Fatal(err)
	}
	s.SetRPFilterDefault(2)
	// The link that the guest wrote keeps its value. The other link follows.
	requireRPFilter(t, s, 1, 2, 2)
	requireRPFilter(t, s, 2, 1, 1)

	// A link that the guest creates later starts with the default.
	a, _ := veth.NewPair(defaultMTU, veth.DefaultBacklogSize)
	err := s.Stack.CreateNICWithOptions(3, newVethNICEndpoint(a), stack.NICOptions{Name: "late", Kind: "veth", MinMTU: ethernetMinMTU, MaxMTU: ethernetMaxMTU})
	if err != nil {
		t.Fatal(err)
	}
	requireRPFilter(t, s, 3, 2, 2)
	s.SetRPFilterDefault(0)
	requireRPFilter(t, s, 3, 0, 0)
}

func TestRPFilterKeepsAnyInteger(t *testing.T) {
	s := ethtoolStack(t, "veth")
	for _, v := range []int32{5, -3, math.MaxInt32, math.MinInt32} {
		s.SetRPFilterAll(v)
		s.SetRPFilterDefault(v)
		if err := s.SetLinkRPFilter(1, v); err != nil {
			t.Fatal(err)
		}
		if s.RPFilterAll() != v || s.RPFilterDefault() != v {
			t.Errorf("all=%d default=%d, want %d", s.RPFilterAll(), s.RPFilterDefault(), v)
		}
		requireRPFilter(t, s, 1, v, v)
	}
}

func TestRPFilterOfAMissingLink(t *testing.T) {
	s := ethtoolStack(t, "veth")
	if _, err := s.LinkRPFilter(9); !errors.Is(err, syserr.ErrUnknownNICID.ToError()) {
		t.Errorf("LinkRPFilter of a missing link = %v, want ENODEV", err)
	}
	if err := s.SetLinkRPFilter(9, 1); err == nil {
		t.Error("SetLinkRPFilter of a missing link succeeded")
	}
}

func TestRPFilterValueEndsWithTheLink(t *testing.T) {
	s := ethtoolStack(t, "veth", "bridge", "vxlan")
	for id := int32(1); id <= 3; id++ {
		if err := s.SetLinkRPFilter(id, 1); err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		s.rpFilter.mu.RLock()
		defer s.rpFilter.mu.RUnlock()
		return len(s.rpFilter.links)
	}
	if err := s.RemoveInterface(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 2 {
		t.Errorf("%d link values after the removal of a link, want 2", got)
	}
	// A link that ends without an event of the stack loses its value at the next write.
	if err := s.Stack.RemoveNIC(2); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLinkRPFilter(3, 2); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 1 {
		t.Errorf("%d link values after the next write, want 1", got)
	}
}

func TestRPFilterOfAMovedLinkStartsAgainFromTheDefault(t *testing.T) {
	src := ethtoolStack(t, "veth")
	dst := ethtoolStack(t)
	dst.SetRPFilterDefault(2)
	if err := src.SetLinkRPFilter(1, 1); err != nil {
		t.Fatal(err)
	}
	// The move of a link calls moveLinkState, then sendDeleteEvent for the old index.
	src.moveLinkState(1, dst, 7)
	src.dropLinkState(1)
	src.rpFilter.mu.RLock()
	left := len(src.rpFilter.links)
	src.rpFilter.mu.RUnlock()
	if left != 0 {
		t.Errorf("the old stack keeps %d link values after the move", left)
	}
	dst.rpFilter.mu.RLock()
	moved := len(dst.rpFilter.links)
	dst.rpFilter.mu.RUnlock()
	if moved != 0 {
		t.Errorf("the new stack holds %d link values after the move, want 0", moved)
	}
}

func TestInheritRPFilterCopiesAllAndDefaultOnly(t *testing.T) {
	root := ethtoolStack(t, "veth")
	root.SetRPFilterAll(1)
	root.SetRPFilterDefault(2)
	if err := root.SetLinkRPFilter(1, 1); err != nil {
		t.Fatal(err)
	}
	child := ethtoolStack(t, "lo")
	child.InheritRPFilter(root)
	if child.RPFilterAll() != 1 || child.RPFilterDefault() != 2 {
		t.Errorf("child all=%d default=%d, want 1 and 2", child.RPFilterAll(), child.RPFilterDefault())
	}
	requireRPFilter(t, child, 1, 2, 2)
	child.SetRPFilterAll(0)
	if root.RPFilterAll() != 1 {
		t.Errorf("root all = %d after a write in the child, want 1", root.RPFilterAll())
	}
}

// TestRPFilterPolicyFeedsTheReversePathCheck checks the policy that NewStack
// installs: the larger rp_filter value of all and the link, and src_valid_mark
// from conf/all or the link.
func TestRPFilterPolicyFeedsTheReversePathCheck(t *testing.T) {
	s := ethtoolStack(t, "veth", "vxlan")
	check := func(step string, id tcpip.NICID, wantMode int32, wantMark bool) {
		t.Helper()
		mode, mark := s.rpFilterPolicy(id)
		if mode != wantMode || mark != wantMark {
			t.Errorf("%s: policy of link %d = (%d, %t), want (%d, %t)", step, id, mode, mark, wantMode, wantMark)
		}
	}
	check("initial", 1, 0, false)

	s.SetRPFilterAll(1)
	check("all 1", 1, 1, false)
	if err := s.SetLinkRPFilter(2, 2); err != nil {
		t.Fatal(err)
	}
	check("link 2 at 2", 2, 2, false)
	check("link 1 follows all", 1, 1, false)

	s.SetSysctlValue(ConfDirIPv4+"/all/src_valid_mark", "1")
	check("all src_valid_mark", 1, 1, true)
	s.SetSysctlValue(ConfDirIPv4+"/all/src_valid_mark", "0")
	if err := s.SetLinkConfValue(2, ConfDirIPv4, "src_valid_mark", 1); err != nil {
		t.Fatal(err)
	}
	check("link src_valid_mark", 2, 2, true)
	check("other link without the mark", 1, 1, false)

	s.SetRPFilterAll(0)
	check("all back to 0", 1, 0, false)
}
