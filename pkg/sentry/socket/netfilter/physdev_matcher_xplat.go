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
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/bits"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the iptables "physdev" match (net/netfilter/xt_physdev.c).
// A rule such as "-m physdev --physdev-is-bridged" selects IP packets that a
// bridge switches between two of its ports. kube-router and Calico use it for
// pod to pod traffic on one node.
//
// The bridge of the stack marks such a packet in stack.PacketBuffer (Bridged,
// BridgedFrom, and BridgedTo). A packet without the mark follows the
// "no nf_bridge" branch of physdev_mt.
// Ref: struct xt_physdev_info in include/uapi/linux/netfilter/xt_physdev.h.

const (
	matcherNamePhysdev = "physdev"

	// physdevInfoSize is sizeof(struct xt_physdev_info): four names of
	// IFNAMSIZ bytes, invert, and bitmask.
	physdevInfoSize = 4*physdevNameLen + 2

	// physdevNameLen is IFNAMSIZ.
	physdevNameLen = linux.IFNAMSIZ

	// The flags of invert and bitmask.
	physdevOpIn      uint8 = 0x01 // XT_PHYSDEV_OP_IN
	physdevOpOut     uint8 = 0x02 // XT_PHYSDEV_OP_OUT
	physdevOpBridged uint8 = 0x04 // XT_PHYSDEV_OP_BRIDGED
	physdevOpIsIn    uint8 = 0x08 // XT_PHYSDEV_OP_ISIN
	physdevOpIsOut   uint8 = 0x10 // XT_PHYSDEV_OP_ISOUT
	physdevOpMask    uint8 = 0x1f // XT_PHYSDEV_OP_MASK
)

// Byte offsets of the fields of struct xt_physdev_info.
const (
	physdevOffInDev   = 0
	physdevOffInMask  = physdevNameLen
	physdevOffOutDev  = 2 * physdevNameLen
	physdevOffOutMask = 3 * physdevNameLen
	physdevOffInvert  = 4 * physdevNameLen
	physdevOffBitmask = physdevOffInvert + 1
)

func init() {
	registerMatchMaker(physdevMarshaler{})
}

// physdevMarshaler implements matchMaker for the physdev match.
type physdevMarshaler struct{}

// name implements matchMaker.name.
func (physdevMarshaler) name() string { return matcherNamePhysdev }

// revision implements matchMaker.revision.
func (physdevMarshaler) revision() uint8 { return 0 }

// marshal implements matchMaker.marshal.
func (physdevMarshaler) marshal(mr matcher) []byte {
	pm := mr.(*PhysdevMatcher)
	data := make([]byte, physdevInfoSize)
	copy(data[physdevOffInDev:], pm.inDev[:])
	copy(data[physdevOffInMask:], pm.inMask[:])
	copy(data[physdevOffOutDev:], pm.outDev[:])
	copy(data[physdevOffOutMask:], pm.outMask[:])
	data[physdevOffInvert] = pm.invert
	data[physdevOffBitmask] = pm.bitmask
	return marshalEntryMatch(matcherNamePhysdev, data)
}

// unmarshal implements matchMaker.unmarshal. It applies the checks of
// physdev_mt_check.
func (physdevMarshaler) unmarshal(_ IDMapper, _ *stack.Stack, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	// WHY: Linux requires the exact aligned size.
	if want := bits.AlignUp(physdevInfoSize, 8); len(buf) != want {
		return nil, fmt.Errorf("physdev: buf has size %d, want %d", len(buf), want)
	}
	pm := &PhysdevMatcher{
		invert:  buf[physdevOffInvert],
		bitmask: buf[physdevOffBitmask],
	}
	copy(pm.inDev[:], buf[physdevOffInDev:])
	copy(pm.inMask[:], buf[physdevOffInMask:])
	copy(pm.outDev[:], buf[physdevOffOutDev:])
	copy(pm.outMask[:], buf[physdevOffOutMask:])
	if pm.bitmask == 0 || pm.bitmask&^physdevOpMask != 0 {
		return nil, fmt.Errorf("physdev: invalid bitmask 0x%x", pm.bitmask)
	}
	// A name needs a NUL byte inside its field, and --physdev-in and
	// --physdev-out need a name.
	if pm.bitmask&physdevOpIn != 0 {
		if err := checkPhysdevName("physdev-in", pm.inDev); err != nil {
			return nil, err
		}
	}
	if pm.bitmask&physdevOpOut != 0 {
		if err := checkPhysdevName("physdev-out", pm.outDev); err != nil {
			return nil, err
		}
	}
	nflog("parsed physdev: bitmask 0x%x invert 0x%x in %q out %q", pm.bitmask, pm.invert, pm.inDev[:], pm.outDev[:])
	return pm, nil
}

func checkPhysdevName(option string, name [physdevNameLen]byte) error {
	if name[0] == 0 {
		return fmt.Errorf("physdev: %s has an empty name", option)
	}
	if !bytes.Contains(name[:], []byte{0}) {
		return fmt.Errorf("physdev: %s name is too long", option)
	}
	return nil
}

// PhysdevMatcher matches the bridge ports of a bridged IP packet.
//
// +stateify savable
type PhysdevMatcher struct {
	// The fields hold struct xt_physdev_info as parsed. Marshal writes them
	// back unchanged.
	inDev, inMask   [physdevNameLen]byte
	outDev, outMask [physdevNameLen]byte
	invert, bitmask uint8
}

// name implements matcher.name.
func (*PhysdevMatcher) name() string { return matcherNamePhysdev }

// revision implements matcher.revision.
func (*PhysdevMatcher) revision() uint8 { return 0 }

// checkHooks implements hookChecker.checkHooks. It is physdev_mt_check_hooks:
// --physdev-out and --physdev-is-out only work in a chain that only the
// FORWARD and POSTROUTING hooks of bridged traffic reach. A chain that the
// OUTPUT hook reaches cannot know the bridge port of the packet.
func (pm *PhysdevMatcher) checkHooks(hookMask uint32) *syserr.Error {
	needsBridged := pm.bitmask&(physdevOpOut|physdevOpIsOut) != 0 &&
		(pm.bitmask&physdevOpBridged == 0 || pm.invert&physdevOpBridged != 0)
	if needsBridged && hookMask&(1<<linux.NF_INET_LOCAL_OUT) != 0 {
		nflog("physdev: --physdev-out and --physdev-is-out need bridged traffic in the OUTPUT chain")
		return syserr.ErrInvalidArgument
	}
	return nil
}

// Match implements stack.Matcher.Match. It follows physdev_mt.
func (pm *PhysdevMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	// notInverted is true when the flag op is not inverted, which means the
	// option needs the property to hold.
	notInverted := func(op uint8) bool { return pm.invert&op == 0 }

	// A packet that no bridge switches has no bridge information. Linux
	// matches it only when every used option is inverted.
	if !pkt.Bridged {
		for _, op := range [...]uint8{physdevOpBridged, physdevOpIsIn, physdevOpIsOut, physdevOpIn, physdevOpOut} {
			if pm.bitmask&op != 0 && notInverted(op) {
				return false, false
			}
		}
		return true, false
	}

	// The bridge sets the port of arrival from the PREROUTING hook on. The
	// port of departure is known only after the bridge looked up the frame.
	inDev, outDev := pkt.BridgedFrom, pkt.BridgedTo
	hasOut := outDev != ""

	// --physdev-is-bridged only holds in the FORWARD and POSTROUTING hooks,
	// where the bridge knows the egress port.
	if pm.bitmask&physdevOpBridged != 0 && hasOut != notInverted(physdevOpBridged) {
		return false, false
	}
	// The port of arrival always exists here, so --physdev-is-in fails only
	// when it is inverted.
	if pm.bitmask&physdevOpIsIn != 0 && !notInverted(physdevOpIsIn) {
		return false, false
	}
	if pm.bitmask&physdevOpIsOut != 0 && hasOut != notInverted(physdevOpIsOut) {
		return false, false
	}

	if pm.bitmask&physdevOpIn != 0 {
		if equal := physdevNameEqual(inDev, &pm.inDev, &pm.inMask); equal != notInverted(physdevOpIn) {
			return false, false
		}
	}
	if pm.bitmask&physdevOpOut == 0 {
		return true, false
	}
	if !hasOut {
		return false, false
	}
	return physdevNameEqual(outDev, &pm.outDev, &pm.outMask) == notInverted(physdevOpOut), false
}

// physdevNameEqual is ifname_compare_aligned. It compares the name with want
// under mask, over the whole IFNAMSIZ bytes of both. Interface names have at
// most IFNAMSIZ - 1 bytes.
func physdevNameEqual(name string, want, mask *[physdevNameLen]byte) bool {
	var padded [physdevNameLen]byte
	copy(padded[:physdevNameLen-1], name)
	var diff byte
	for i := range padded {
		diff |= (padded[i] ^ want[i]) & mask[i]
	}
	return diff == 0
}

// hookChecker is implemented by matchers whose check function depends on the
// hooks that reach the rule, as the hook_mask of struct xt_mtchk_param does in
// Linux.
type hookChecker interface {
	checkHooks(hookMask uint32) *syserr.Error
}

// checkMatcherHooks runs checkHooks of every matcher in table with the set of
// hooks that reach its rule. It is the part of mark_source_chains that gives
// the hook_mask to the check function of a Linux match. A rule that no chain
// reaches has an empty mask. The caller must run it after the parse of the
// jumps.
func checkMatcherHooks(table stack.Table, ipv6 bool) *syserr.Error {
	needed := false
	for _, rule := range table.Rules {
		for _, m := range rule.Matchers {
			if _, ok := m.(hookChecker); ok {
				needed = true
			}
		}
	}
	if !needed {
		return nil
	}

	masks := make([]uint32, len(table.Rules))
	for hook, ruleIdx := range table.BuiltinChains {
		if table.ValidHooks()&(1<<hook) != 0 {
			markHookMask(table, ruleIdx, 1<<hook, masks, make([]bool, len(table.Rules)), ipv6)
		}
	}
	for ruleIdx, rule := range table.Rules {
		for _, m := range rule.Matchers {
			if hc, ok := m.(hookChecker); ok {
				if err := hc.checkHooks(masks[ruleIdx]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// markHookMask adds bit to the mask of each rule that a packet of the hook can
// reach from the rule at ruleIdx. It walks a chain like checkChainTargets.
func markHookMask(table stack.Table, ruleIdx int, bit uint32, masks []uint32, visited []bool, ipv6 bool) {
	for ruleIdx >= 0 && ruleIdx < len(table.Rules) && !visited[ruleIdx] {
		visited[ruleIdx] = true
		masks[ruleIdx] |= bit

		rule := table.Rules[ruleIdx]
		if jump, ok := rule.Target.(*JumpTarget); ok {
			markHookMask(table, jump.RuleNum, bit, masks, visited, ipv6)
		}
		if isUnconditionalFinalRule(rule, ipv6) {
			return
		}
		ruleIdx++
	}
}
