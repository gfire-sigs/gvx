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

package netfilter

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// noSet is the info of a target set that the rule does not use.
var noSet = setInfo{index: ipset.InvalidID}

// setTargetSpec is the user space view of the target data of the "SET"
// target.
type setTargetSpec struct {
	rev              uint8
	add, del, mapSet setInfo
	flags, timeout   uint32
}

// entry lays out the xt_entry_target of the revision as the iptables binary
// writes it. Every padding byte has the value 0xaa.
func (s setTargetSpec) entry() []byte {
	size := map[uint8]int{1: setTargetSizeV1, 2: setTargetSizeV2, 3: setTargetSizeV3}[s.rev]
	buf := bytes.Repeat([]byte{0xaa}, size)
	hdr := linux.XTEntryTarget{TargetSize: uint16(size), Revision: s.rev}
	copy(hdr.Name[:], SetTargetName)
	hdr.MarshalUnsafe(buf)
	putInfo := func(off int, info setInfo) {
		binary.LittleEndian.PutUint16(buf[off:], uint16(info.index))
		buf[off+2], buf[off+3] = info.dim, info.flags
	}
	putInfo(setTargetOffAdd, s.add)
	putInfo(setTargetOffDel, s.del)
	switch s.rev {
	case 2:
		binary.LittleEndian.PutUint32(buf[setTargetV2OffFlags:], s.flags)
		binary.LittleEndian.PutUint32(buf[setTargetV2OffTimeout:], s.timeout)
	case 3:
		putInfo(setTargetV3OffMap, s.mapSet)
		binary.LittleEndian.PutUint32(buf[setTargetV3OffFlags:], s.flags)
		binary.LittleEndian.PutUint32(buf[setTargetV3OffTimeout:], s.timeout)
	}
	return buf
}

func parseSetTarget(t *testing.T, filter stack.IPHeaderFilter, spec setTargetSpec) stack.Target {
	t.Helper()
	tgt, err := parseTarget(filter, spec.entry(), false, "mangle")
	if err != nil {
		t.Fatalf("parseTarget(%+v): %v", spec, err)
	}
	if _, ok := tgt.(*setTarget); !ok {
		t.Fatalf("parseTarget returned %T, want *setTarget", tgt)
	}
	return tgt
}

// bindSetTarget parses spec and binds it to the stack of env.
func (e *setEnv) bindSetTarget(t *testing.T, spec setTargetSpec) stack.Target {
	t.Helper()
	tgt := parseSetTarget(t, stack.EmptyFilter4(), spec)
	if err := bindMatcherStacks(e.stk, []stack.Rule{{Target: tgt}}); err != nil {
		t.Fatalf("bind %+v: %v", spec, err)
	}
	return tgt
}

func runTarget(t *testing.T, tgt stack.Target, pkt *stack.PacketBuffer) {
	t.Helper()
	verdict, _ := tgt.Action(pkt, stack.Prerouting, nil, nil)
	if verdict != stack.RuleContinue {
		t.Fatalf("Action returned verdict %v, want RuleContinue", verdict)
	}
}

func TestSetTargetRoundTripKeepsTheBytes(t *testing.T) {
	for _, spec := range []setTargetSpec{
		{rev: 1, add: setInfo{3, 1, testDimOneSrc}, del: noSet},
		{rev: 2, add: setInfo{4, 2, testDimOneSrc | testDimTwoSrc}, del: setInfo{5, 1, 0}, flags: uint32(ipset.FlagExist), timeout: 600},
		{rev: 3, add: noSet, del: noSet, mapSet: setInfo{6, 1, testDimOneSrc}, flags: uint32(ipset.FlagMapSkbmark | ipset.FlagMapSkbprio)},
	} {
		want := spec.entry()
		for name, filter := range map[string]stack.IPHeaderFilter{"ipv4": stack.EmptyFilter4(), "ipv6": stack.EmptyFilter6()} {
			tgt := parseSetTarget(t, filter, spec)
			if got := marshalTarget(tgt); !bytes.Equal(got, want) {
				t.Errorf("rev %d %s: marshal = %x, want %x", spec.rev, name, got, want)
			}
		}
	}
}

func TestSetTargetRejectsWrongSize(t *testing.T) {
	buf := setTargetSpec{rev: 3, add: noSet, del: noSet, mapSet: noSet}.entry()
	for _, size := range []int{linux.SizeOfXTEntryTarget, len(buf) - 8, len(buf) + 8} {
		bad := make([]byte, size)
		copy(bad, buf)
		if _, err := parseTarget(stack.EmptyFilter4(), bad, false, "mangle"); err == nil {
			t.Errorf("parseTarget accepted a revision 3 target of %d bytes", size)
		}
	}
}

func TestSetTargetAddsAndDeletesThePacketSource(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "seen", "hash:ip", ipset.FamilyIPv4, nil)
	member := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 1, flags: testDimOneSrc})
	add := env.bindSetTarget(t, setTargetSpec{rev: 1, add: setInfo{id, 1, testDimOneSrc}, del: noSet})
	del := env.bindSetTarget(t, setTargetSpec{rev: 1, add: noSet, del: setInfo{id, 1, testDimOneSrc}})

	pkt := buildPacket(t, tcpPacket("192.0.2.77", "198.51.100.1", 1000, 80))
	if matchSet(t, member, pkt) {
		t.Fatal("the source was a member before the target ran")
	}
	runTarget(t, add, pkt)
	if !matchSet(t, member, pkt) {
		t.Error("--add-set did not add the packet source")
	}
	if matchSet(t, member, buildPacket(t, tcpPacket("192.0.2.78", "198.51.100.1", 1000, 80))) {
		t.Error("--add-set added another source")
	}
	runTarget(t, del, pkt)
	if matchSet(t, member, pkt) {
		t.Error("--del-set did not remove the packet source")
	}
}

func TestSetTargetAddAndDelInOneRule(t *testing.T) {
	env := newSetEnv(t)
	hot := env.create(t, "hot", "hash:ip", ipset.FamilyIPv4, nil)
	cold := env.create(t, "cold", "hash:ip", ipset.FamilyIPv4, nil)
	env.add(t, "cold", hostElement("192.0.2.5"))
	inHot := env.bindSetMatch(t, setMatchSpec{rev: 4, index: hot, dim: 1, flags: testDimOneSrc})
	inCold := env.bindSetMatch(t, setMatchSpec{rev: 4, index: cold, dim: 1, flags: testDimOneSrc})
	tgt := env.bindSetTarget(t, setTargetSpec{rev: 2, add: setInfo{hot, 1, testDimOneSrc}, del: setInfo{cold, 1, testDimOneSrc}, timeout: uint32(ipset.NoTimeout)})

	pkt := buildPacket(t, tcpPacket("192.0.2.5", "198.51.100.1", 1000, 80))
	runTarget(t, tgt, pkt)
	if !matchSet(t, inHot, pkt) || matchSet(t, inCold, pkt) {
		t.Error("one rule with --add-set and --del-set did not move the source from one set to the other")
	}
}

func TestSetTargetHashIPPortUsesTheDestinationPort(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "flows", "hash:ip,port", ipset.FamilyIPv4, nil)
	tgt := env.bindSetTarget(t, setTargetSpec{rev: 1, add: setInfo{id, 2, testDimOneSrc}, del: noSet})
	runTarget(t, tgt, buildPacket(t, tcpPacket("192.0.2.5", "198.51.100.1", 1000, 8443)))

	match := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 2, flags: testDimOneSrc})
	if !matchSet(t, match, buildPacket(t, tcpPacket("192.0.2.5", "203.0.113.1", 2000, 8443))) {
		t.Error("the element with the source and the destination port did not match")
	}
	if matchSet(t, match, buildPacket(t, tcpPacket("192.0.2.5", "203.0.113.1", 8443, 80))) {
		t.Error("the source port matched as a destination port")
	}
}

func TestSetTargetTimeoutOfRevision2(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "timed", "hash:ip", ipset.FamilyIPv4, func(p *ipset.CreateParams) {
		p.Given |= ipset.GivenTimeout
		p.Timeout = 300
	})
	member := env.bindSetMatch(t, setMatchSpec{rev: 4, index: id, dim: 1, flags: testDimOneSrc})
	withTimeout := env.bindSetTarget(t, setTargetSpec{rev: 2, add: setInfo{id, 1, testDimOneSrc}, del: noSet, timeout: 10})
	withDefault := env.bindSetTarget(t, setTargetSpec{rev: 1, add: setInfo{id, 1, testDimOneSrc}, del: noSet})

	runTarget(t, withTimeout, buildPacket(t, tcpPacket("192.0.2.1", "198.51.100.1", 1, 2)))
	runTarget(t, withDefault, buildPacket(t, tcpPacket("192.0.2.2", "198.51.100.1", 1, 2)))
	for _, src := range []string{"192.0.2.1", "192.0.2.2"} {
		if !matchSet(t, member, buildPacket(t, tcpPacket(src, "198.51.100.1", 1, 2))) {
			t.Fatalf("%s is no member right after the add", src)
		}
	}
	env.clock.Advance(11 * time.Second)
	if matchSet(t, member, buildPacket(t, tcpPacket("192.0.2.1", "198.51.100.1", 1, 2))) {
		t.Error("--timeout 10 left the element in the set after 11 seconds")
	}
	if !matchSet(t, member, buildPacket(t, tcpPacket("192.0.2.2", "198.51.100.1", 1, 2))) {
		t.Error("an element without a rule timeout lost its set timeout of 300 seconds")
	}
	env.clock.Advance(300 * time.Second)
	if matchSet(t, member, buildPacket(t, tcpPacket("192.0.2.2", "198.51.100.1", 1, 2))) {
		t.Error("the default timeout of the set did not apply")
	}
}

func TestSetTargetMapsSkbinfoToTheMark(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "marks", "hash:ip", ipset.FamilyIPv4, func(p *ipset.CreateParams) {
		p.CadtFlags = ipset.CadtWithSkbinfo
	})
	env.add(t, "marks", ipset.Element{
		Has: ipset.HasIP | ipset.HasSkbMark, IP: ipsetAddr("192.0.2.1"), SkbMark: uint64(0x10)<<32 | 0xff,
	})
	mapFlags := uint32(ipset.FlagMapSkbmark)
	mapSrc := env.bindSetTarget(t, setTargetSpec{rev: 3, add: noSet, del: noSet, mapSet: setInfo{id, 1, testDimOneSrc}, flags: mapFlags})
	mapSrcInverted := env.bindSetTarget(t, setTargetSpec{rev: 3, add: noSet, del: noSet, mapSet: setInfo{id, 1, testDimOneSrc | testInvMatch}, flags: mapFlags})
	noMapFlag := env.bindSetTarget(t, setTargetSpec{rev: 3, add: noSet, del: noSet, mapSet: setInfo{id, 1, testDimOneSrc}})

	hit := buildPacket(t, tcpPacket("192.0.2.1", "198.51.100.1", 1, 2))
	hit.Mark = 0x1234
	runTarget(t, mapSrc, hit)
	// The mark keeps the bits outside of the mask and xors the element mark.
	if want := uint32(0x1200 ^ 0x10); hit.Mark != want {
		t.Errorf("mark after --map-set = 0x%x, want 0x%x", hit.Mark, want)
	}

	miss := buildPacket(t, tcpPacket("192.0.2.2", "198.51.100.1", 1, 2))
	miss.Mark = 0x1234
	runTarget(t, mapSrc, miss)
	if miss.Mark != 0x1234 {
		t.Errorf("mark of a packet that is no member = 0x%x, want 0x1234", miss.Mark)
	}

	inverted := buildPacket(t, tcpPacket("192.0.2.1", "198.51.100.1", 1, 2))
	inverted.Mark = 0x1234
	runTarget(t, mapSrcInverted, inverted)
	if inverted.Mark != 0x1234 {
		t.Errorf("mark with an inverted --map-set on a member = 0x%x, want 0x1234", inverted.Mark)
	}

	plain := buildPacket(t, tcpPacket("192.0.2.1", "198.51.100.1", 1, 2))
	plain.Mark = 0x1234
	runTarget(t, noMapFlag, plain)
	if plain.Mark != 0x1234 {
		t.Errorf("mark of --map-set without the skbmark flag = 0x%x, want 0x1234", plain.Mark)
	}
}

func TestSetTargetIgnoresInvalidIndexes(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "idle", "hash:ip", ipset.FamilyIPv4, nil)
	tgt := env.bindSetTarget(t, setTargetSpec{rev: 3, add: noSet, del: noSet, mapSet: noSet})
	runTarget(t, tgt, buildPacket(t, tcpPacket("192.0.2.1", "198.51.100.1", 1, 2)))
	if err := env.reg.Destroy("idle", false, false); err != nil {
		t.Errorf("Destroy = %v, want nil: a target without sets holds no reference (index %d)", err, id)
	}
}

func TestSetTargetHoldsItsSetsUntilReleased(t *testing.T) {
	env := newSetEnv(t)
	add := env.create(t, "add", "hash:ip", ipset.FamilyIPv4, nil)
	del := env.create(t, "del", "hash:ip", ipset.FamilyIPv4, nil)
	mapped := env.create(t, "mapped", "hash:ip", ipset.FamilyIPv4, nil)
	tgt := parseSetTarget(t, stack.EmptyFilter4(), setTargetSpec{rev: 3, add: setInfo{add, 1, 0}, del: setInfo{del, 1, 0}, mapSet: setInfo{mapped, 1, 0}})
	rules := []stack.Rule{{Target: tgt}}
	if err := bindMatcherStacks(env.stk, rules); err != nil {
		t.Fatalf("bind: %v", err)
	}
	for _, name := range []string{"add", "del", "mapped"} {
		if err := env.reg.Destroy(name, false, false); !isIPSetError(err, ipset.ErrBusy) {
			t.Errorf("Destroy(%q) while the target holds it = %v, want the busy error", name, err)
		}
	}
	releaseMatcherStacks(rules)
	for _, name := range []string{"add", "del", "mapped"} {
		if err := env.reg.Destroy(name, false, false); err != nil {
			t.Errorf("Destroy(%q) after the release = %v, want nil", name, err)
		}
	}
}

func TestSetTargetRejectsUnknownIndexAndDimension(t *testing.T) {
	env := newSetEnv(t)
	good := env.create(t, "good", "hash:ip", ipset.FamilyIPv4, nil)
	tests := []struct {
		name string
		spec setTargetSpec
		want *syserr.Error
	}{
		{"unknown add_set", setTargetSpec{rev: 3, add: setInfo{99, 1, 0}, del: noSet, mapSet: noSet}, syserr.ErrNoFileOrDir},
		{"unknown del_set", setTargetSpec{rev: 3, add: setInfo{good, 1, 0}, del: setInfo{99, 1, 0}, mapSet: noSet}, syserr.ErrNoFileOrDir},
		{"unknown map_set", setTargetSpec{rev: 3, add: setInfo{good, 1, 0}, del: setInfo{good, 1, 0}, mapSet: setInfo{99, 1, 0}}, syserr.ErrNoFileOrDir},
		{"dimension over the limit", setTargetSpec{rev: 2, add: setInfo{good, 1, 0}, del: setInfo{good, 7, 0}}, syserr.ErrRange},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tgt := parseSetTarget(t, stack.EmptyFilter4(), tc.spec)
			if err := bindMatcherStacks(env.stk, []stack.Rule{{Target: tgt}}); err != tc.want {
				t.Fatalf("bind = %v, want %v", err, tc.want)
			}
			if err := env.reg.Destroy("good", false, false); err != nil {
				t.Fatalf("Destroy after the failed bind = %v, want nil: the failed bind kept a reference", err)
			}
			// Recreate the set for the next case.
			env.create(t, "good", "hash:ip", ipset.FamilyIPv4, nil)
		})
	}
}

func TestBindFailureReleasesTheEarlierRules(t *testing.T) {
	env := newSetEnv(t)
	good := env.create(t, "good", "hash:ip", ipset.FamilyIPv4, nil)
	matcher := parseSetMatch(t, stack.EmptyFilter4(), setMatchSpec{rev: 4, index: good, dim: 1})
	target := parseSetTarget(t, stack.EmptyFilter4(), setTargetSpec{rev: 1, add: setInfo{good, 1, 0}, del: noSet})
	broken := parseSetTarget(t, stack.EmptyFilter4(), setTargetSpec{rev: 1, add: setInfo{99, 1, 0}, del: noSet})
	rules := []stack.Rule{
		{Matchers: []stack.Matcher{matcher}, Target: target},
		{Target: broken},
	}
	if err := bindMatcherStacks(env.stk, rules); err != syserr.ErrNoFileOrDir {
		t.Fatalf("bind = %v, want ENOENT", err)
	}
	if err := env.reg.Destroy("good", false, false); err != nil {
		t.Errorf("Destroy after the failed bind = %v, want nil", err)
	}
}
