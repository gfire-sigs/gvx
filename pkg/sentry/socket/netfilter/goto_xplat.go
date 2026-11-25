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

import "z.gfire.dev/gvx/pkg/tcpip/stack"

// IPT_F_GOTO is the flag of struct ipt_ip that turns the jump of a rule into a
// goto. ip6tables uses linux.IP6T_F_GOTO for the same flag.
const iptFGoto = 0x02

// GotoTarget implements stack.Target for "-g chain" rules without modifying
// upstream JumpTarget or netfilter_state_autogen.go. Because it embeds
// JumpTarget and promotes JumpTarget.id, wire marshaling must go through
// marshalTargetForWire rather than marshalTarget directly.
//
// +stateify savable
type GotoTarget struct {
	JumpTarget
}

// Action implements stack.Target.Action.
func (gt *GotoTarget) Action(*stack.PacketBuffer, stack.Hook, *stack.Route, stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	return stack.RuleGoto, gt.RuleNum
}

// applyGoto converts a JumpTarget into a GotoTarget when the entry sets the
// goto flag. A goto enters the chain without a return address, so the end of
// that chain returns to the caller of the current chain. The flag has no effect
// on any other target.
func applyGoto(target stack.Target, flags, gotoFlag uint8) stack.Target {
	if jump, ok := target.(*JumpTarget); ok && flags&gotoFlag != 0 {
		return &GotoTarget{JumpTarget: *jump}
	}
	return target
}

// gotoFlags returns the goto flag of the entry for a rule, or 0 when the rule
// is not a goto.
func gotoFlags(target stack.Target, gotoFlag uint8) uint8 {
	if _, ok := target.(*GotoTarget); ok {
		return gotoFlag
	}
	return 0
}

// asJumpTarget returns the underlying JumpTarget for either a jump or a goto
// target so chain offset resolution and graph checks handle both uniformly.
func asJumpTarget(target stack.Target) (*JumpTarget, bool) {
	switch t := target.(type) {
	case *JumpTarget:
		return t, true
	case *GotoTarget:
		return &t.JumpTarget, true
	default:
		return nil, false
	}
}

// marshalTargetForWire serializes target into an xtables target payload,
// encoding GotoTarget as a standard jump target whose goto bit lives in the
// enclosing entry flags.
func marshalTargetForWire(target stack.Target) []byte {
	if gt, ok := target.(*GotoTarget); ok {
		return marshalTarget(&gt.JumpTarget)
	}
	return marshalTarget(target)
}
