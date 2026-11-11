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

package ipset

import (
	"bytes"
	"context"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func TestStateRoundTripAllSetKindsAndExpirations(t *testing.T) {
	clock := faketime.NewManualClock()
	stk := stack.New(stack.Options{Clock: clock})
	t.Cleanup(stk.Destroy)

	mod := NewModule()
	mod.SetMaxSets(16)
	reg := ForStack(stk, mod)

	create(t, reg, "hip", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.CadtFlags = CadtWithComment | CadtWithCounters | CadtWithSkbinfo
		p.Timeout = 30
		p.Given = GivenCadtFlags | GivenTimeout
	})
	create(t, reg, "hnet", "hash:net", FamilyIPv4, nil)
	create(t, reg, "hipport", "hash:ip,port", FamilyIPv4, nil)
	create(t, reg, "hnetnet", "hash:net,net", FamilyIPv4, nil)
	create(t, reg, "bport", "bitmap:port", FamilyUnspec, func(p *CreateParams) {
		p.PortFrom = 1000
		p.PortTo = 1015
		p.CadtFlags = CadtWithCounters
		p.Timeout = 10
		p.Given = GivenPortFrom | GivenPortTo | GivenCadtFlags | GivenTimeout
	})
	create(t, reg, "lset", "list:set", FamilyUnspec, nil)

	timedHost := Element{
		Has:     HasIP | HasTimeout | HasComment | HasSkbMark,
		IP:      ip4("10.10.0.1"),
		Timeout: 10,
		Comment: "timed-entry",
		SkbMark: uint64(0x1234)<<32 | 0xffff,
	}
	if got := uadt(reg, "hip", AdtAdd, timedHost, 0); got != 0 {
		t.Fatalf("add hip timedHost = %d", got)
	}
	if got := uadt(reg, "hip", AdtAdd, hostElem("10.10.0.2"), 0); got != 0 {
		t.Fatalf("add hip second = %d", got)
	}
	if got := uadt(reg, "hnet", AdtAdd, netElem("192.168.10.0", 24), 0); got != 0 {
		t.Fatalf("add hnet = %d", got)
	}
	if got := uadt(reg, "hipport", AdtAdd, portElem("10.20.0.1", 6, 443), 0); got != 0 {
		t.Fatalf("add hipport = %d", got)
	}
	netNetElem := Element{
		Has:   HasIP | HasCIDR | HasIP2 | HasCIDR2,
		IP:    ip4("172.16.0.0"),
		CIDR:  16,
		IP2:   ip4("10.30.0.0"),
		CIDR2: 24,
	}
	if got := uadt(reg, "hnetnet", AdtAdd, netNetElem, 0); got != 0 {
		t.Fatalf("add hnetnet = %d", got)
	}
	portOnly := Element{Has: HasPort | HasTimeout, Port: 1005, Timeout: 10}
	if got := uadt(reg, "bport", AdtAdd, portOnly, 0); got != 0 {
		t.Fatalf("add bport = %d", got)
	}
	if got := uadt(reg, "lset", AdtAdd, Element{Has: HasName, Name: "hip"}, 0); got != 0 {
		t.Fatalf("add lset member hip = %d", got)
	}
	if got := uadt(reg, "lset", AdtAdd, Element{Has: HasName, Name: "bport"}, 0); got != 0 {
		t.Fatalf("add lset member bport = %d", got)
	}

	hipID, _, ok := reg.Lookup("hip")
	if !ok {
		t.Fatal("Lookup(hip) failed")
	}
	pkt := Packet{
		Family:  FamilyIPv4,
		Src:     ip4("10.10.0.1"),
		Dst:     ip4("10.99.0.1"),
		Proto:   6,
		SrcPort: 12345,
		DstPort: 1005,
		PortsOK: true,
		Len:     128,
	}
	opt := KOpt{Dim: 1, Flags: KDimOneSrc, CmdFlags: FlagMapSkbmark, Timeout: NoTimeout}
	if reg.Test(hipID, &pkt, &opt) <= 0 {
		t.Fatal("kernel Test(hip) before save did not match")
	}

	// Advance 3 seconds of the 10-second timeout before checkpoint.
	clock.Advance(3 * time.Second)

	dump, err := reg.NewDump("hip", true)
	if err != nil {
		t.Fatalf("NewDump(hip): %v", err)
	}
	defer dump.Close()

	var buf bytes.Buffer
	graph := []any{stk, mod, dump}
	if _, err := state.Save(context.Background(), &buf, &graph); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	var loaded []any
	if _, err := state.Load(context.Background(), &buf, &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoredStk := loaded[0].(*stack.Stack)
	t.Cleanup(restoredStk.Destroy)
	restoredMod := loaded[1].(*Module)
	restoredDump := loaded[2].(*Dump)
	defer restoredDump.Close()

	if got := restoredMod.MaxSets(); got != 16 {
		t.Errorf("restored Module.MaxSets() = %d, want 16", got)
	}
	restoredReg := ExistingForStack(restoredStk)
	if restoredReg == nil {
		t.Fatal("ExistingForStack(restoredStk) = nil")
	}

	// Verify active Dump cursor survives checkpoint and restore.
	if _, _, more, err := restoredDump.Next(); !more || err != nil {
		t.Fatalf("restoredDump.Next: more=%v err=%v", more, err)
	}
	var dumped int
	for {
		_, ok := restoredDump.Cursor().Peek()
		if !ok {
			break
		}
		dumped++
		restoredDump.Cursor().Advance()
	}
	if dumped != 2 {
		t.Errorf("restoredDump yielded %d elements, want 2", dumped)
	}

	// Verify membership across all restored set kinds.
	if got := uadt(restoredReg, "hnet", AdtTest, hostElem("192.168.10.55"), 0); got <= 0 {
		t.Errorf("restored hnet test = %d, want match", got)
	}
	if got := uadt(restoredReg, "hipport", AdtTest, portElem("10.20.0.1", 6, 443), 0); got <= 0 {
		t.Errorf("restored hipport test = %d, want match", got)
	}
	testNetNet := Element{Has: HasIP | HasCIDR | HasIP2 | HasCIDR2, IP: ip4("172.16.5.9"), CIDR: 32, IP2: ip4("10.30.0.7"), CIDR2: 32}
	if got := uadt(restoredReg, "hnetnet", AdtTest, testNetNet, 0); got <= 0 {
		t.Errorf("restored hnetnet test = %d, want match", got)
	}
	if got := uadt(restoredReg, "bport", AdtTest, Element{Has: HasPort, Port: 1005}, 0); got <= 0 {
		t.Errorf("restored bport test = %d, want match", got)
	}

	lsetID, _, ok := restoredReg.Lookup("lset")
	if !ok {
		t.Fatal("Lookup(lset) after restore failed")
	}
	dstPortOpt := KOpt{Dim: 1, Flags: 0, Timeout: NoTimeout}
	if restoredReg.Test(lsetID, &pkt, &dstPortOpt) <= 0 {
		t.Error("restored list:set failed to match bitmap:port member")
	}

	// Verify comment, skbinfo, and packet/byte counters survived on hip.
	elems := listAll(t, restoredReg, "hip")
	var foundTimed bool
	for _, e := range elems {
		if e.IP == ip4("10.10.0.1") {
			foundTimed = true
			if e.Comment != "timed-entry" {
				t.Errorf("Comment = %q, want timed-entry", e.Comment)
			}
			if e.Packets != 1 || e.Bytes != 128 {
				t.Errorf("counters = (%d, %d), want (1, 128)", e.Packets, e.Bytes)
			}
			if e.SkbMark != (uint64(0x1234)<<32 | 0xffff) {
				t.Errorf("SkbMark = %#x, want %#x", e.SkbMark, uint64(0x1234)<<32|0xffff)
			}
		}
	}
	if !foundTimed {
		t.Fatal("timed entry 10.10.0.1 missing after restore")
	}

	// Advance restored ManualClock: 5s more (total 8s < 10s) keeps timed entries;
	// 3s more (total 11s > 10s) expires both hash:ip and bitmap:port timed entries.
	restoredClock := restoredStk.Clock().(*faketime.ManualClock)
	restoredClock.Advance(5 * time.Second)
	if got := uadt(restoredReg, "hip", AdtTest, hostElem("10.10.0.1"), 0); got <= 0 {
		t.Errorf("timed hip entry expired early at 8s: %d", got)
	}
	if got := uadt(restoredReg, "bport", AdtTest, Element{Has: HasPort, Port: 1005}, 0); got <= 0 {
		t.Errorf("timed bport entry expired early at 8s: %d", got)
	}

	restoredClock.Advance(3 * time.Second)
	if got := uadt(restoredReg, "hip", AdtTest, hostElem("10.10.0.1"), 0); got > 0 {
		t.Errorf("timed hip entry still matched at 11s: %d", got)
	}
	if got := uadt(restoredReg, "bport", AdtTest, Element{Has: HasPort, Port: 1005}, 0); got > 0 {
		t.Errorf("timed bport entry still matched at 11s: %d", got)
	}
	if got := uadt(restoredReg, "hip", AdtTest, hostElem("10.10.0.2"), 0); got <= 0 {
		t.Errorf("permanent hip entry disappeared: %d", got)
	}
}

func TestTwoStacksIsolateSetsBeforeAndAfterSaveRestore(t *testing.T) {
	stkA := stack.New(stack.Options{Clock: faketime.NewManualClock()})
	stkB := stack.New(stack.Options{Clock: faketime.NewManualClock()})
	t.Cleanup(stkA.Destroy)
	t.Cleanup(stkB.Destroy)

	regA := ForStack(stkA, nil)
	regB := ForStack(stkB, nil)
	create(t, regA, "allow", "hash:ip", FamilyIPv4, nil)
	create(t, regB, "allow", "hash:ip", FamilyIPv4, nil)
	if got := uadt(regA, "allow", AdtAdd, hostElem("10.1.0.1"), 0); got != 0 {
		t.Fatalf("add stkA = %d", got)
	}
	if got := uadt(regB, "allow", AdtAdd, hostElem("10.2.0.2"), 0); got != 0 {
		t.Fatalf("add stkB = %d", got)
	}
	if uadt(regA, "allow", AdtTest, hostElem("10.2.0.2"), 0) > 0 || uadt(regB, "allow", AdtTest, hostElem("10.1.0.1"), 0) > 0 {
		t.Fatal("stacks shared ipset entries before save")
	}

	roundTrip := func(s *stack.Stack) *stack.Stack {
		var buf bytes.Buffer
		if _, err := state.Save(context.Background(), &buf, &s); err != nil {
			t.Fatalf("state.Save: %v", err)
		}
		var out *stack.Stack
		if _, err := state.Load(context.Background(), &buf, &out); err != nil {
			t.Fatalf("state.Load: %v", err)
		}
		t.Cleanup(out.Destroy)
		return out
	}

	restoredA := roundTrip(stkA)
	restoredB := roundTrip(stkB)
	rA := ExistingForStack(restoredA)
	rB := ExistingForStack(restoredB)
	if rA == nil || rB == nil || rA == rB {
		t.Fatalf("restored registries = (%p, %p), want distinct non-nil instances", rA, rB)
	}
	if uadt(rA, "allow", AdtTest, hostElem("10.1.0.1"), 0) <= 0 || uadt(rA, "allow", AdtTest, hostElem("10.2.0.2"), 0) > 0 {
		t.Error("restoredA has unexpected ipset membership")
	}
	if uadt(rB, "allow", AdtTest, hostElem("10.2.0.2"), 0) <= 0 || uadt(rB, "allow", AdtTest, hostElem("10.1.0.1"), 0) > 0 {
		t.Error("restoredB has unexpected ipset membership")
	}
	if got := uadt(rA, "allow", AdtAdd, hostElem("10.1.0.99"), 0); got != 0 {
		t.Fatalf("post-restore add rA = %d", got)
	}
	if uadt(rB, "allow", AdtTest, hostElem("10.1.0.99"), 0) > 0 {
		t.Error("post-restore mutation on restoredA leaked into restoredB")
	}
}
